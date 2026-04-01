"""
GithubProvider is a provider that interacts with GitHub.
"""

import dataclasses

import pydantic
from github import Github

from keep.contextmanager.contextmanager import ContextManager
from keep.providers.base.base_provider import BaseProvider
from keep.providers.models.provider_config import ProviderConfig
from keep.providers.models.provider_method import ProviderMethod


@pydantic.dataclasses.dataclass
class GithubProviderAuthConfig:
    """
    GithubProviderAuthConfig is a class that represents the authentication configuration for the GithubProvider.
    """

    access_token: str | None = dataclasses.field(
        metadata={
            "required": True,
            "description": "GitHub Access Token",
            "sensitive": True,
        }
    )


class GithubProvider(BaseProvider):
    """
    Enrich alerts with data from GitHub.
    """

    PROVIDER_DISPLAY_NAME = "GitHub"
    PROVIDER_CATEGORY = ["Developer Tools"]
    PROVIDER_METHODS = [
        ProviderMethod(
            name="get_last_commits",
            func_name="get_last_commits",
            description="Get the N last commits from a GitHub repository",
            type="view",
        ),
        ProviderMethod(
            name="get_last_releases",
            func_name="get_last_releases",
            description="Get the N last releases and their changelog from a GitHub repository",
            type="view",
        ),
        ProviderMethod(
            name="create_issue",
            func_name="create_issue",
            description="Create a new issue in a GitHub repository",
            type="action",
        ),
    ]

    def __init__(
        self, context_manager: ContextManager, provider_id: str, config: ProviderConfig
    ):
        super().__init__(context_manager, provider_id, config)
        self.client = self.__generate_client()

    def get_last_commits(self, repository: str, n: int = 10):
        """
        Get the last N commits from a GitHub repository.
        Args:
            repository (str): The GitHub repository to get the commits from.
            n (int): The number of commits to get.
        """
        self.logger.info(f"Getting last {n} commits from {repository}")
        # get only the name so if the repo is
        # https://github.com/keephq/keep -> keephq/keep
        if repository.startswith("https://github.com"):
            repository = repository.split("https://github.com/")[1]

        repo = self.client.get_repo(repository)
        commits = repo.get_commits()
        self.logger.info(f"Found {commits.totalCount} commits")
        commits = [commit.raw_data for commit in commits[:n]]
        return commits

    def get_last_releases(self, repository: str, n: int = 10):
        """
        Get the last N releases from a GitHub repository.
        Args:
            repository (str): The GitHub repository to get the releases from.
            n (int): The number of releases to get.
        """
        self.logger.info(f"Getting last {n} releases from {repository}")
        repo = self.client.get_repo(repository)
        releases = repo.get_releases()
        self.logger.info(f"Found {releases.totalCount} releases")
        return [release.raw_data for release in releases[:n]]

    def create_issue(
        self,
        repository: str,
        title: str,
        body: str = "",
        labels: list = None,
        assignees: list = None,
    ):
        """
        Create a new issue in a GitHub repository.
        Args:
            repository (str): The GitHub repository to create the issue in.
            title (str): The title of the issue.
            body (str): The body/description of the issue.
            labels (list): List of label names to apply to the issue.
            assignees (list): List of usernames to assign to the issue.
        Returns:
            dict: The created issue data.
        """
        self.logger.info(f"Creating issue in {repository}: {title}")

        # Normalize repository name
        if repository.startswith("https://github.com"):
            repository = repository.split("https://github.com/")[1]

        repo = self.client.get_repo(repository)

        # Create the issue
        issue = repo.create_issue(
            title=title,
            body=body,
            labels=labels or [],
            assignees=assignees or [],
        )

        self.logger.info(f"Issue created successfully: {issue.html_url}")

        return {
            "number": issue.number,
            "title": issue.title,
            "body": issue.body,
            "state": issue.state,
            "html_url": issue.html_url,
            "created_at": str(issue.created_at),
            "labels": [label.name for label in issue.labels],
            "assignees": [assignee.login for assignee in issue.assignees],
        }

    def __generate_client(self):
        # Should get an access token once we have a real use case for GitHub provider
        if self.authentication_config.access_token:
            client = Github(self.authentication_config.access_token)
        else:
            client = Github()
        return client

    def dispose(self):
        """
        Dispose of the provider.
        """
        pass

    def validate_config(self):
        self.authentication_config = GithubProviderAuthConfig(
            **self.config.authentication
        )

    def _query(self, command_type: str, **kwargs: dict):
        """
        Query GitHub for information using different command types.

        Args:
            command_type (str): The type of query to execute (get_last_commits, get_last_releases)
            **kwargs: Additional parameters for the specific command

        Returns:
            Query results based on command_type
        """
        if command_type == "get_last_commits":
            return self.get_last_commits(
                repository=kwargs.get("repository"),
                n=kwargs.get("n", 10)
            )

        elif command_type == "get_last_releases":
            return self.get_last_releases(
                repository=kwargs.get("repository"),
                n=kwargs.get("n", 10)
            )

        else:
            raise NotImplementedError(
                f"Query command_type '{command_type}' is not implemented. "
                f"Available: get_last_commits, get_last_releases"
            )

    def _notify(self, **kwargs):
        """
        Execute actions on GitHub.

        Args:
            type (str): The type of action to execute (create_issue)
            repository (str): The repository for create_issue action
            title (str): The title for create_issue action
            body (str): The body for create_issue action
            labels (list): Labels for create_issue action
            assignees (list): Assignees for create_issue action
            run_action (str): The action to run (legacy GitHub Actions workflow trigger)
            workflow (str): The workflow to run
            repo_name (str): The repository name
            repo_owner (str): The repository owner
            ref (str): The ref to use
            inputs (dict): The inputs to use

        Returns:
            Action results based on type or run_action
        """
        # Handle create_issue action
        if kwargs.get("type") == "create_issue":
            return self.create_issue(
                repository=kwargs.get("repository"),
                title=kwargs.get("title"),
                body=kwargs.get("body", ""),
                labels=kwargs.get("labels"),
                assignees=kwargs.get("assignees"),
            )

        # Legacy: run GitHub Actions workflow
        if "run_action" in kwargs:
            workflow_name = kwargs.get("workflow")
            repo_name = kwargs.get("repo_name")
            repo_owner = kwargs.get("repo_owner")
            ref = kwargs.get("ref", "main")
            inputs = kwargs.get("inputs", {})

            # Initialize the GitHub client
            github_client = self.__generate_client()

            # Get the repository
            repo = github_client.get_repo(f"{repo_owner}/{repo_name}")

            # Trigger the workflow
            workflow = repo.get_workflow(workflow_name)
            run = workflow.create_dispatch(ref, inputs)
            return run


class GithubStarsProvider(GithubProvider):
    """
    GithubStarsProvider is a class that provides a way to read stars from a GitHub repository.
    """

    def __init__(
        self, context_manager: ContextManager, provider_id: str, config: ProviderConfig
    ):
        super().__init__(context_manager, provider_id, config)

    def _query(
        self,
        repository: str,
        previous_stars_count: int = 0,
        last_stargazer: str = "",
        **kwargs: dict,
    ) -> dict:
        repo = self.client.get_repo(repository)
        stars_count = repo.stargazers_count
        new_stargazers = []

        if not previous_stars_count:
            previous_stars_count = 0

        self.logger.debug(f"Previous stargazers: {previous_stars_count}")
        self.logger.debug(f"New stargazers: {stars_count - int(previous_stars_count)}")

        stargazers_with_dates = []
        # If we have the last stargazer login name, use it as index
        if last_stargazer:
            stargazers_with_dates = list(repo.get_stargazers_with_dates())
            last_stargazer_index = next(
                (
                    i
                    for i, item in enumerate(stargazers_with_dates)
                    if item.user.login == last_stargazer
                ),
                -1,
            )
            if last_stargazer_index == -1:
                stargazers_with_dates = []
            else:
                stargazers_with_dates = stargazers_with_dates[
                    last_stargazer_index + 1 :
                ]
        # If we dont, use the previous stars count as an index
        elif previous_stars_count and int(previous_stars_count) > 0:
            stargazers_with_dates = list(repo.get_stargazers_with_dates())[
                int(previous_stars_count) :
            ]

        # Iterate new stargazers if there are any
        for stargazer in stargazers_with_dates:
            new_stargazers.append(
                {
                    "username": stargazer.user.login,
                    "starred_at": str(stargazer.starred_at),
                }
            )
            self.logger.debug(f"New stargazer: {stargazer.user.login}")

        # Save last stargazer name so we can use it next iteration
        last_stargazer = (
            new_stargazers[-1]["username"]
            if len(new_stargazers) >= 1
            else last_stargazer
        )

        return {
            "stars": stars_count,
            "new_stargazers": new_stargazers,
            "new_stargazers_count": len(new_stargazers),
            "last_stargazer": last_stargazer,
        }


if __name__ == "__main__":
    import os

    context_manager = ContextManager(
        tenant_id="singletenant",
        workflow_id="test",
    )
    github_provider = GithubProvider(
        context_manager,
        "test",
        ProviderConfig(authentication={"access_token": os.environ.get("GITHUB_PAT")}),
    )

    result = github_provider.get_last_commits("keephq/keep", 10)
    print(result)
