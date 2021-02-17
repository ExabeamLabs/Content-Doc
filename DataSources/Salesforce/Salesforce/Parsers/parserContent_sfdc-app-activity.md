#### Parser Content
```Java
{
Name = sfdc-app-activity
  Vendor = Salesforce
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """SFDCLogType=""", """SFDCLogId=""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """SFDCLogDate="({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d.\d\d\d(\-|\+)\d+)""",
    """PAGE_NAME="?({object}[^",]+)""",
    """ENTITY_NAME="?({object}[^",]+)""",
    """object="?({object}[^",]+)""",
    """METHOD_NAME="?({activity}[^",]+)""",
    """action="?({activity}[^",]+)""",
    """CLIENT_NAME="?({user_agent}[^",]+)""",
    """CLIENT_NAME="?[^",]+?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
    """CLIENT_IP="?({src_ip}[A-Fa-f:\d.]+)""",
    """Username="?({user_email}[^"\s,@]+@[^"\s,]+)""",
    """USER_ID="?({user}[^"\s,]+)""",
    """REQUEST_SIZE="?({bytes}\d+)""",
  ]
}
```