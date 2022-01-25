#### Parser Content
```Java
{
Name = s-liebsoft-app-login
    Vendor = BeyondTrust
    Product = BeyondTrust Privileged Identity
    Lms = Splunk
    DataType = "app-login"
    TimeFormat = "yyyy-dd-MM'T'HH:mm:ss"
    Conditions = [ """sEventID="EVENT_ID_WEBAPP_LOGIN"""","""<Event"""]
    Fields = [
        """\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[^\s]{1,2000})\s{1,100}<Event""",
        """dtPostTime="({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})""",
        """sOriginatingApplicationName="({app}[^"]{1,2000})""",
        """sIpAddress="({src_ip}[a-fA-F\d.:]{1,2000})""",
        """sLoginName="(({domain}[^"]{1,2000})\\)?({user}[^"]{1,2000})""",
        """sOriginatingSystem="({dest_host}[^"]{1,2000})"""
    ]
  }
```