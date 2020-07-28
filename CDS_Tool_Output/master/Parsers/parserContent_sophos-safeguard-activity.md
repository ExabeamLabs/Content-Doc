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
    """EVT_ID="({alert_id}\d+)""",
    """EVT_APPLICATION_ID="({app}[^"]+)""",
    """EVT_MACHINE_NAME="({host}[^"]+)""",
    """EVT_MACHINE_DOMAIN="({domain}[^"]+)""",
    """EVT_MACHINE_GUID="({target_guid}[^"]+)""",
    """EVT_USER_NAME="({user}[^"]+)""",
    """EVT_USER_DOMAIN="({domain}[^"]+)""",
    """EVT_USER_GUID="({user_logon_guid}[^"]+)""",
    """EVT_LOG_TIME="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """EVT_LOG_TIME="[^"]+", ({additional_info}.+), EVT_CREATION_DATE=""",
    """EVT_CREATION_DATE="({time_created}[^"]+)""",
    """EVT_MODIFY_DATE="({time_modified}[^"]+)""",
    """EVT_CREATED_BY="({created_by}[^."]+)""",
    """EVT_MODIFIED_BY="({updated_by}[^."]+)""",
  ]
  DupFields = ["host->src_host"]
}
```