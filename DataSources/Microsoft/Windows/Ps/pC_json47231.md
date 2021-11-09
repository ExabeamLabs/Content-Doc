#### Parser Content
```Java
{
Name = json-4723-1
  DataType = "windows-password-change"
  Conditions = [ """"event_id":4723""", """An attempt was made to change an account's password""" ]
  Fields = ${WinParserTemplates.json-windows-events-1.Fields}[
    """({event_name}An attempt was made to change an account's password)""",
    """"TargetSid"{1,20}:"{1,20}({target_user_sid}[^"]{1,2000})""",
    """"hostname"{1,20}:"{1,20}(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}|({dest_host}[^"]{1,2000}))""",
  ]
}
json-windows-events-1 = {
  Vendor = Microsoft
  Product = Windows
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)\s[^\s]{1,2000}\sSkyformation""",
    """"{1,20}created"{1,20}:"{1,20}({time}[^"]{1,2000})""",
    """requestClientApplication=({app}[^=]{1,2000}?)\s\w+=""",
    """({event_name}An account was logged off)""",
    """"keywords"{1,20}:\["{1,20}({outcome}[^"]{1,2000})""",
    """"pid"{1,20}:({pid}\d{1,100})""",
    """thread"{1,20}:[^@]{1,2000}?"{1,20}id"{1,20}:({thread_id}\d{1,100})""",
    """"TargetUserName"{1,20}:"{1,20}(None|({target_user}[^"]{1,2000}))""",
    """"TargetDomainName"{1,20}:"{1,20}({domain}[^"]{1,2000})""",
    """"TargetLogonId"{1,20}:"{1,20}({logon_id}[^"]{1,2000})""",
    """"LogonType"{1,20}:"{1,20}({logon_type}[^"]{1,2000})""",
    """"TargetUserSid"{1,20}:"{1,20}({user_sid}[^"<,]{1,2000})""",
    """"record_id"{1,20}:({record_id}\d{1,100})""",
    """"task"{1,20}:"{1,20}({task_name}[^"]{1,2000})""",
    """"event_id"{1,20}:({event_code}\d{1,100})""",
    """"(?:winlog\.)?computer_name"{1,20}:"{1,20}({src_host}[^"]{1,2000})""",
    """"hostname"{1,20}:"{1,20}({host}[^"]{1,2000})""",
    """"action"{1,20}:"{1,20}({action}[^"]{1,2000})""",
    """"os":[^@]{1,2000}?"name":"({os}[^"]{1,2000})""",
    """"SubjectLogonId"{1,20}:"{1,20}({logon_id}[^"]{1,2000})""",
    """"{1,20}activity_id"{1,20}:"{1,20}\{({activity_id}[^}]{1,2000})""",
    """"{1,20}ProviderName"{1,20}:"{1,20}({provider_name}[^"]{1,2000})""",
    """"{1,20}SubjectUserSid"{1,20}:"{1,20}({user_sid}[^"<,]{1,2000})""",
    """"{1,20}SubjectDomainName"{1,20}:"{1,20}({domain}[^"]{1,2000})""",
    """"user"{1,20}:"{1,20}(SYSTEM|-|({user}[^@"]{1,2000}))""",
    """"{1,20}SubjectUserName"{1,20}:"{1,20}(SYSTEM|-|({user}[^"]{1,2000}))""",
    """"{1,20}PrivilegeList"{1,20}:"{1,20}(-|({privileges}[^"]{1,2000}))""",
    """"{1,20}SidHistory"{1,20}:"{1,20}(-|({sid_history}[^"]{1,2000}))""",
    """"Keywords":"({outcome}[^"]{1,2000})"""
  ]
  DupFields = ["event_id->event_code"]}
```