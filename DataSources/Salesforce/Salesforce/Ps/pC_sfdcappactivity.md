#### Parser Content
```Java
{
Name = sfdc-app-activity
  Vendor = Salesforce
  Product = Salesforce
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """SFDCLogType=""", """SFDCLogId=""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """SFDCLogDate="({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d.\d\d\d(\-|\+)\d{1,100})""",
    """PAGE_NAME="?({object}[^",]{1,2000})""",
    """ENTITY_NAME="?({object}[^",]{1,2000})""",
    """object="?({object}[^",]{1,2000})""",
    """METHOD_NAME="?({activity}[^",]{1,2000})""",
    """action="?({activity}[^",]{1,2000})""",
    """CLIENT_NAME="?({user_agent}[^",]{1,2000})""",
    """CLIENT_IP="?({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """Username="?({user_email}[^"\s,@]{1,2000}@[^"\s,]{1,2000})""",
    """USER_ID="?({user}[^"\s,]{1,2000})""",
    """REQUEST_SIZE="?({bytes}\d{1,100})""",
  ]


}
```