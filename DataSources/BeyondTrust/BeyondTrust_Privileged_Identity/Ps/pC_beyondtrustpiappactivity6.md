#### Parser Content
```Java
{
Name = beyondtrust-pi-app-activity-6
  Conditions = [ """EVENT_ID_JOB_STARTING_PASSWORD_CHANGE_ON_SYSTEM""", """2013""", """sEventID""", """dwBasicEventType""", """sOriginatingApplicationName""", """dwAppSpecificEventID""", """Privileged Identity""" ]

beyondtrust-pi-app-activity = {
  Vendor = BeyondTrust
  Product = BeyondTrust Privileged Identity
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-dd-MM'T'HH:mm:ss"
  Fields = [
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """dtPostTime=\\?"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """hostname":"({host}[^"]{1,2000})"""",
    """\ssIpAddress=\\?"({src_ip}[a-fA-F\d:.]{1,2000})""",
    """\ssEventID=\\?"({activity}[^"]{1,2000}?)\\?"""",
    """\ssOriginatingApplicationName =\\?"({app}[^"\\]{1,2000}?)\\?"""",
    """dwAppSpecificEventID=\\?"({event_code}\d{1,100})""",
    """\ssOriginatingAccount=\\?"(({domain}[^\\]{1,2000})\\{1,20})?({user}[^"\\]{1,2000}?)\\?"""",
    """\ssOriginatingSystem=\\?"({dest_host}[^"\\]{1,2000}?)\\?"""",
    """key=\\?"AccountToElevate\\?"\svalue=\\?"(({account_domain}[^\\]{1,2000})\\{1,20})?({account}[^"\\]{1,2000}?)\\?"""",
    """\ssMessage=\\?"({additional_info}[^\n]{1,2000}?)\\r","exa_rsc":"""
  ]
  DupFields = [ "activity->event_name" 
}
```