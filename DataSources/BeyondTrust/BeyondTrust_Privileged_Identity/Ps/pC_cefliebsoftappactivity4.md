#### Parser Content
```Java
{
Name = cef-liebsoft-app-activity-4
  Conditions = [ """CEF:""", """|Liebsoft|""", """|EVENT_ID_JOB_ACCOUNT_ELEVATION_DEELEVATION_FAILED|""" ]
}
cef-liebsoft-app-activity = {
  Vendor = BeyondTrust
  Product = BeyondTrust Privileged Identity
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Fields = [
    """CEF:([^\|]{0,2000}\|){4}({activity}[^\|]{1,2000})""",
    """CEF:([^\|]{0,2000}\|){5}({outcome}[^\|]{1,2000})""",
    """\Wrt=({time}\w+ \d{1,100} \d\d\d\d \d{1,100}:\d{1,100}:\d{1,100})""",
    """\Wshost=({host}[\w\-.]{1,2000})""",
    """\(running as user (({account_domain}[^\s\\]{1,2000})\\+)?({account}[^\s\\\)]{1,2000})\)""",
    """sntdom=({account_domain}[^\s]{1,2000})""",
    """suser=({account}[^\s]{1,2000})""",
    """\(user (({domain}[^\s\\]{1,2000})\\+)?({user}[^\s\\\)]{1,2000})\) \-\s{1,100}({additional_info}.+?)\s{1,100}(\w+=|$)""",
    """dntdom=({domain}[^\s]{1,2000})""",
    """duser=({user}[^\s]{1,2000})""",
    """group '({object}[^\']{1,2000})' on system """,
    """dhost=({dest_host}[\w\-.]{1,2000})""",
    """({app}Liebsoft)""",
  ]}
```