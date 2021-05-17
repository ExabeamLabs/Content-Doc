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
    """\w{3}\s\d\d\s\d\d:\d\d:\d\d\s({host}[^\s]{1,2000})""",
    """dtPostTime="({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """sEventID="({activity}[^"]{1,2000})""",
    """\(running as user (({account_domain}[^\s\\]{1,2000})\\+)?({account}[^\s\\\)]{1,2000})\)""",
    """"AccountToElevate"\s{1,100}value="(({domain}[^\s\\]{1,2000})\\+)?({user}[^\s\\"]{1,2000})""",
    """group '({object}[^\']{1,2000})' on system """,
    """"TargetSystem"\s{1,100}value="({dest_host}[^"]{1,2000})""",
    """OriginatingApplicationName="({app}[^"]{1,2000})"""
  ]
}
```