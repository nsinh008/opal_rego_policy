package app
# By default, deny requests.
default allow = false
# Allow admins to do anything.
allow {
    user_is_admin
}
# Allow the action if the user is granted permission to perform the action.
allow {
    # Find grants for the user.
    some grant
    user_is_granted[grant]
    # Check if the grant permits the action.
    # input.action == grant.action
    # input.resource == grant.resource
}
# user_is_admin is true if...
user_is_admin {
    # for some `i`...
    some i
    # "admin" is the `i`-th element in the user->role mappings for the identified user.
    data.app_site_user_roles[input.application]["sites"][input.site][input.user]["roles"][i] == "admin"
}
# user_is_granted is a set of grants for the user identified in the request.
# The `grant` will be contained if the set `user_is_granted` for every...
user_is_granted[grant] {
    some i, j
    # `role` assigned an element of the user_roles for this user...
    role := data.app_site_user_roles[input.application]["sites"][input.site][input.user]["roles"][i]
    # `grant` assigned a single grant from the grants list for 'role'...
    grant := data.app_role_permissions[input.application][role][j]
}
