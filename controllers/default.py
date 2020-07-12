# -*- coding: utf-8 -*-

@auth.requires_login()
def api_get_jwt():
    session.forget()
    if not request.env.request_method == 'GET': raise HTTP(403)
    import jwt
    import json
    import datetime
    secret = 'secret'
    role = db((db.auth_membership.id==auth.user.id) & (db.auth_membership.group_id==db.auth_group.id)).select(db.auth_group.role).first().role
    sub = auth.user.username
    exp = datetime.datetime.utcnow() + datetime.timedelta(seconds=60)
    payload = {'sub':sub, 'role': role, 'exp': exp}
    encoded_jwt = jwt.encode(payload, secret, algorithm='HS256' )

    return encoded_jwt


# ---- Action for login/register/etc (required for auth) -----
def user():
    """
    exposes:
    http://..../[app]/default/user/login
    http://..../[app]/default/user/logout
    http://..../[app]/default/user/register
    http://..../[app]/default/user/profile
    http://..../[app]/default/user/retrieve_password
    http://..../[app]/default/user/change_password
    http://..../[app]/default/user/bulk_register
    use @auth.requires_login()
        @auth.requires_membership('group name')
        @auth.requires_permission('read','table name',record_id)
    to decorate functions that need access control
    also notice there is http://..../[app]/appadmin/manage/auth to allow administrator to manage users
    """
    return dict(form=auth())

# ---- action to server uploaded static content (required) ---
@cache.action()
def download():
    """
    allows downloading of uploaded files
    http://..../[app]/default/download/[filename]
    """
    return response.download(request, db)
