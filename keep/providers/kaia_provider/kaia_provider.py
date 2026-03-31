import json
import dataclasses
import time
import pydantic
import requests

from keep.contextmanager.contextmanager import ContextManager
from keep.providers.base.base_provider import BaseProvider
from keep.providers.models.provider_config import ProviderConfig


@pydantic.dataclasses.dataclass
class KaiaProviderAuthConfig:
    """Authentication configuration for Kaia provider using Azure AD."""

    tenant_id: str = dataclasses.field(
        metadata={
            "required": True,
            "description": "Azure AD Tenant ID",
            "sensitive": True,
        },
    )
    client_id: str = dataclasses.field(
        metadata={
            "required": True,
            "description": "Azure AD Client ID (Application ID)",
            "sensitive": True,
        },
    )
    client_secret: str = dataclasses.field(
        metadata={
            "required": True,
            "description": "Azure AD Client Secret",
            "sensitive": True,
        },
    )
    resource_id: str = dataclasses.field(
        metadata={
            "required": True,
            "description": "Kaia Resource ID for Azure AD authentication",
            "sensitive": False,
        },
    )
    base_url: str = dataclasses.field(
        metadata={
            "required": True,
            "description": "Kaia Base URL (e.g., https://your-vertical-kaia-url)",
            "sensitive": False,
        },
    )
    confluence_mcp_url: str = dataclasses.field(
        default="https://iop-mcpatl-confluence-jiratools.apps.axsvocp1.service.inditex.grp/mcp/",
        metadata={
            "required": False,
            "description": "Confluence MCP URL (optional, for fetching Confluence pages)",
            "sensitive": False,
        },
    )
    confluence_pat: str = dataclasses.field(
        default="",
        metadata={
            "required": False,
            "description": "Confluence Personal Access Token (optional, for MCP authentication)",
            "sensitive": True,
        },
    )


class KaiaProvider(BaseProvider):
    """
    Kaia AI Provider for Keep workflows.

    Provides integration with Inditex's Kaia platform for AI agent interactions.
    Supports multiple LLM providers (OpenAI, Anthropic, Google) through a unified API.
    """

    PROVIDER_DISPLAY_NAME = "Kaia"
    PROVIDER_CATEGORY = ["AI"]

    def __init__(
        self, context_manager: ContextManager, provider_id: str, config: ProviderConfig
    ):
        super().__init__(context_manager, provider_id, config)
        self._access_token = None
        self._token_expires_at = 0

    def validate_config(self):
        """Validate the provider configuration."""
        self.authentication_config = KaiaProviderAuthConfig(
            **self.config.authentication
        )

    def dispose(self):
        """Clean up resources."""
        self._access_token = None
        self._token_expires_at = 0

    def validate_scopes(self) -> dict[str, bool | str]:
        """Validate provider scopes/permissions."""
        scopes = {}
        try:
            # Try to get an access token as a basic validation
            token = self._get_access_token()
            scopes["authenticated"] = bool(token)
        except Exception as e:
            scopes["authenticated"] = str(e)
        return scopes

    def _get_access_token(self) -> str:
        """
        Get Azure AD access token using Client Credentials flow.
        Caches the token until it expires.

        Returns:
            str: Access token for Kaia API
        """
        # Return cached token if still valid (with 5min buffer)
        if self._access_token and time.time() < (self._token_expires_at - 300):
            return self._access_token

        token_url = f"https://login.microsoftonline.com/{self.authentication_config.tenant_id}/oauth2/token"

        payload = {
            "grant_type": "client_credentials",
            "client_id": self.authentication_config.client_id,
            "client_secret": self.authentication_config.client_secret,
            "resource": self.authentication_config.resource_id,
        }

        self.logger.debug("Requesting Azure AD access token")
        response = requests.post(token_url, data=payload, timeout=30)

        if response.status_code != 200:
            error_msg = f"Failed to get access token: {response.status_code} - {response.text}"
            self.logger.error(error_msg)
            raise Exception(error_msg)

        token_data = response.json()
        self._access_token = token_data["access_token"]
        # expires_in is in seconds
        expires_in = token_data.get("expires_in", 3600)
        # Cast to int in case the API returns it as a string
        self._token_expires_at = time.time() + int(expires_in)

        self.logger.debug("Successfully obtained access token")
        return self._access_token

    def _fetch_confluence_page(self, page_id: str) -> str:
        """
        Fetch Confluence page content using Confluence MCP.

        Args:
            page_id (str): Confluence page ID or shortlink

        Returns:
            str: HTML content of the Confluence page
        """
        if not self.authentication_config.confluence_pat:
            raise Exception("Confluence PAT not configured. Set confluence_pat in provider config.")

        mcp_url = self.authentication_config.confluence_mcp_url

        # MCP request payload for getting page content
        # Based on MCP protocol: https://modelcontextprotocol.io/
        mcp_payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "confluence-get-page",
                "arguments": {
                    "pageId": page_id
                }
            }
        }

        headers = {
            "Authorization": f"Token {self.authentication_config.confluence_pat}",
            "Content-Type": "application/json",
        }

        self.logger.debug(f"Fetching Confluence page {page_id} from MCP: {mcp_url}")

        try:
            response = requests.post(
                mcp_url,
                headers=headers,
                json=mcp_payload,
                timeout=30,
            )

            if response.status_code != 200:
                error_msg = f"Confluence MCP error: {response.status_code} - {response.text}"
                self.logger.error(error_msg)
                raise Exception(error_msg)

            result = response.json()

            # MCP response structure: {jsonrpc, id, result: {content: [{type, text}]}}
            if "result" in result and "content" in result["result"]:
                content_blocks = result["result"]["content"]
                # Extract text from all content blocks
                page_content = "\n".join([
                    block.get("text", "")
                    for block in content_blocks
                    if block.get("type") == "text"
                ])

                self.logger.debug(f"Successfully fetched Confluence page {page_id}")
                return page_content
            else:
                raise Exception(f"Unexpected MCP response format: {result}")

        except Exception as e:
            self.logger.error(f"Error fetching Confluence page: {str(e)}")
            raise

    def _query(
        self,
        prompt: str,
        model: str = "gpt-4.1",
        max_tokens: int | None = None,
        temperature: float = 1.0,
        system_prompt: str | None = None,
        structured_output_format: dict | None = None,
        confluence_page_id: str | None = None,
    ):
        """
        Query the Kaia API with the given prompt.

        Args:
            prompt (str): The user prompt/message to send to the model
            model (str): The model to use (e.g., "gpt-4.1", "claude-sonnet-4.5", "gpt-5.1")
            max_tokens (int, optional): Maximum number of tokens to generate
            temperature (float): Temperature for response generation (default: 1.0)
            system_prompt (str, optional): System prompt to guide the model
            structured_output_format (dict, optional): JSON schema for structured output
            confluence_page_id (str, optional): Confluence page ID to fetch and include in prompt

        Returns:
            dict: Response containing the AI-generated text

        Example:
            provider.query(
                prompt="What is the capital of Spain?",
                model="gpt-4.1",
                max_tokens=100
            )

            # With Confluence page
            provider.query(
                prompt="Find contact for Grafana in ES market",
                confluence_page_id="417520181",
                model="gpt-4.1"
            )
        """
        access_token = self._get_access_token()

        # Fetch Confluence page content if requested
        confluence_content = None
        if confluence_page_id:
            try:
                confluence_content = self._fetch_confluence_page(confluence_page_id)
                self.logger.debug(f"Fetched Confluence content: {len(confluence_content)} characters")
            except Exception as e:
                self.logger.warning(f"Failed to fetch Confluence page: {str(e)}")
                # Continue without Confluence content

        # Build the full prompt with Confluence content if available
        full_prompt = prompt
        if confluence_content:
            full_prompt = f"{prompt}\n\nCONFLUENCE PAGE CONTENT:\n{confluence_content}"

        # Build the messages list
        messages = []

        # Add system message if provided
        if system_prompt:
            messages.append({
                "type": "system",
                "content_blocks": [
                    {"type": "text", "text": system_prompt}
                ]
            })

        # Add user message
        messages.append({
            "type": "human",
            "content_blocks": [
                {"type": "text", "text": full_prompt}
            ]
        })

        # Build LLM config
        llm_config = {
            "model_name": model,
        }

        # Add optional parameters
        if temperature is not None:
            llm_config["temperature"] = temperature
        if max_tokens is not None:
            llm_config["max_tokens"] = max_tokens

        # Build request payload
        payload = {
            "messages": messages,
            "llm_config": llm_config,
        }

        # Add structured output if provided
        if structured_output_format:
            # Kaia uses output_format_schema for structured output
            if "json_schema" in structured_output_format:
                json_schema = structured_output_format["json_schema"]
                # Kaia expects: {name, parameters (the schema), strict}
                payload["output_format_schema"] = {
                    "name": json_schema.get("name"),
                    "parameters": json_schema.get("schema"),
                    "strict": json_schema.get("strict", True)
                }

        # Make the API request
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }

        url = f"{self.authentication_config.base_url}/api/v2/agent/invoke"

        self.logger.debug(f"Calling Kaia API: {url}")
        self.logger.debug(f"Using model: {model}")

        response = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=45,  # 45 second timeout for AI responses
        )

        if response.status_code != 200:
            error_msg = f"Kaia API error: {response.status_code} - {response.text}"
            self.logger.error(error_msg)
            raise Exception(error_msg)

        result = response.json()

        # Extract the text response
        response_text = result.get("text", "")

        # Try to parse as JSON if structured output was requested
        if structured_output_format:
            try:
                response_text = json.loads(response_text)
            except json.JSONDecodeError:
                self.logger.warning("Structured output requested but response is not valid JSON")

        return {
            "response": response_text,
            "model": result.get("model_name"),
            "usage": result.get("usage", {}),
        }


if __name__ == "__main__":
    import os
    import logging

    logging.basicConfig(level=logging.DEBUG, handlers=[logging.StreamHandler()])
    context_manager = ContextManager(
        tenant_id="singletenant",
        workflow_id="test",
    )

    # Get credentials from environment variables
    config = ProviderConfig(
        description="Kaia AI Provider",
        authentication={
            "tenant_id": os.environ.get("AZURE_TENANT_ID"),
            "client_id": os.environ.get("AZURE_CLIENT_ID"),
            "client_secret": os.environ.get("AZURE_CLIENT_SECRET"),
            "resource_id": os.environ.get("KAIA_RESOURCE_ID"),
            "base_url": os.environ.get("KAIA_BASE_URL"),
        },
    )

    provider = KaiaProvider(
        context_manager=context_manager,
        provider_id="kaia_provider",
        config=config,
    )

    # Test basic query
    print("\n=== Test 1: Basic Query ===")
    print(
        provider.query(
            prompt="What is the capital of Spain?",
            model="gpt-4.1",
            max_tokens=100,
        )
    )

    # Test with system prompt
    print("\n=== Test 2: With System Prompt ===")
    print(
        provider.query(
            prompt="Analyze this alert: High CPU usage detected on production server",
            model="gpt-4.1",
            system_prompt="You are a DevOps expert analyzing system alerts. Be concise.",
            max_tokens=200,
        )
    )

    # Test structured output
    print("\n=== Test 3: Structured Output ===")
    print(
        provider.query(
            prompt="Categorize this alert: Database connection timeout in payment service",
            model="gpt-4.1",
            structured_output_format={
                "json_schema": {
                    "name": "alert_categorization",
                    "schema": {
                        "type": "object",
                        "properties": {
                            "severity": {
                                "type": "string",
                                "enum": ["low", "medium", "high", "critical"],
                            },
                            "category": {
                                "type": "string",
                                "enum": ["infrastructure", "application", "database", "network"],
                            },
                            "requires_immediate_action": {
                                "type": "boolean",
                            },
                        },
                        "required": ["severity", "category", "requires_immediate_action"],
                        "additionalProperties": False,
                    },
                    "strict": True,
                }
            },
            max_tokens=100,
        )
    )
