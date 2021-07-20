#### Parser Content
```Java
{
Name = sophos-safeguard-activity
  Vendor = Sophos
  Product = Sophos SafeGuard
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """EVT_LOG_MESSAGE_ID=""", """EVT_APPLICATION_ID=""", """EVT_MACHINE_GUID=""", """EVT_USER_GUID=""", """EVT_LOG_MESSAGE_PREV=""", """EVT_LOG_MESSAGE_SEQ=""" ]
  Fields = [
    """EVT_ID="({alert_id}\d{1,100})""",
    """EVT_APPLICATION_ID="({app}[^"]{1,2000})""",
    """EVT_MACHINE_NAME="({host}[^"]{1,2000})""",
    """EVT_MACHINE_DOMAIN="({domain}[^"]{1,2000})""",
    """EVT_MACHINE_GUID="({target_guid}[^"]{1,2000})""",
    """EVT_USER_NAME="({user}[^"]{1,2000})""",
    """EVT_USER_DOMAIN="({domain}[^"]{1,2000})""",
    """EVT_USER_GUID="({user_logon_guid}[^"]{1,2000})""",
    """EVT_LOG_TIME="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """EVT_LOG_TIME="[^"]{1,2000}", ({additional_info}.+), EVT_CREATION_DATE=""",
    """EVT_CREATION_DATE="({time_created}[^"]{1,2000})""",
    """EVT_MODIFY_DATE="({time_modified}[^"]{1,2000})""",
    """EVT_CREATED_BY="({created_by}[^."]{1,2000})""",
    """EVT_MODIFIED_BY="({updated_by}[^."]{1,2000})""",
  ]
  DupFields = ["host->src_host"]
}
```