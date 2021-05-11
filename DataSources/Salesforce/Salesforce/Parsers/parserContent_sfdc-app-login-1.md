#### Parser Content
```Java
{
Name = sfdc-app-login-1
  Vendor = Salesforce
  Product = Salesforce
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """SFDCLogType="""", """SFDCLogId="""", """EVENT_TYPE="Login"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """SFDCLogDate="({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d.\d\d\d(\-|\+)\d{1,100})""",
    """BROWSER_TYPE="({user_agent}[^"]+)""",
    """BROWSER_TYPE=".+?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
    """TLS_PROTOCOL="({protocol}[^"]+)""",
    """SOURCE_IP="({src_ip}[A-Fa-f:\d.]+)""",
    """USER_ID="({user}[^"\s]+)""",
    """LOGIN_STATUS="({outcome}[^"]+)""",
    """USER_NAME="({user_email}[^@]+({email_domain}[^"]+))""", 
  ]
}
```