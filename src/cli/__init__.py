from .main import main as main_token_inspector
from .user_roles import main as main_user_roles


def token_inspector():
    return main_token_inspector()

def user_roles():
    return main_user_roles()


if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(description="Keycloak Token Inspector CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand for token inspector
    parser_token = subparsers.add_parser("token-inspector", help="Inspect Keycloak tokens")

    # Subcommand for user roles
    parser_roles = subparsers.add_parser("user-roles", help="Retrieve effective user roles from Keycloak")

    args = parser.parse_args()

    if args.command == "token-inspector":
        exit_code = token_inspector()
    elif args.command == "user-roles":
        exit_code = user_roles()
    else:
        print(f"Unknown command: {args.command}", file=sys.stderr)
        exit_code = 1

    sys.exit(exit_code)
