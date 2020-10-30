#### Parser Content
```Java
{
Name = beyondtrust-pi-app-activity
  Vendor = BeyondTrust
  Product = BeyondTrust Privileged Identity
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-dd-MM'T'HH:mm:ss"
  Conditions = [ """sEventID="EVENT_ID_JOB_ACCOUNT_ELEVATED"""", """sOriginatingApplicationName="Privileged Identity"""", """<Event """]
  Fields = [
    """\w{3}\s\d\d\s\d\d:\d\d:\d\d\s({host}[^\s]+)""",
    """dtPostTime="({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """sEventID="({activity}[^"]+)""",
    """\(running as user (({account_domain}[^\s\\]+)\\+)?({account}[^\s\\\)]+)\)""",
    """"AccountToElevate"\s+value="(({domain}[^\s\\]+)\\+)?({user}[^\s\\"]+)""",
    """group '({object}[^\']+)' on system """,
    """"TargetSystem"\s+value="({dest_host}[^"]+)""",
    """OriginatingApplicationName="({app}[^"]+)"""
  ]
}
```