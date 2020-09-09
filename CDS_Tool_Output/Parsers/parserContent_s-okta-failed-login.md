#### Parser Content
```Java
{
Name = s-okta-failed-login
    DataType = "failed-app-login"
    Conditions = [ """"displayMessage": "User login to Okta"""", """"legacyEventType": "core.user_auth.login_failed"""" ]
    DupFields = [ "additional_info->failure_reason" ]
  }
```