# The former all-users Startup hook treated every non-console session as a
# ChildStream child and elevated Sunshine. Exact ownership was not verified.
# This entry point remains only to fail safely if an old hook still invokes it.
throw 'ChildStream automatic Sunshine startup is disabled pending exact child-session ownership and privilege validation. No process was started.'
