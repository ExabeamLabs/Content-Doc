#### Parser Content
```Java
{
Name = sk4-json-4722
  DataType = "windows-ds-access"
  Conditions = [""""event_id":4722""", """|Skyformation""", """Microsoft-Windows-Security-Auditing""", """A user account was enabled"""]
  Fields = ${WinParserTemplates.json-windows-events-1.Fields}[
    """({event_name}A user account was enabled)""",
  ]
}
json-windows-events-1 = {
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)\s[^\s]+\sSkyformation""",
    """"{1,20}created"{1,20}:"{1,20}({time}[^"]+)""",
    """requestClientApplication=({app}[^=]+?)\s\w+=""",
    """({event_name}An account was logged off)""",
    """"keywords"{1,20}:\["{1,20}({outcome}[^"]+)""",
    """"pid"{1,20}:({pid}\d{1,100})""",
    """thread"{1,20}:[^@]+?"{1,20}id"{1,20}:({thread_id}\d{1,100})""",
    """"TargetUserName"{1,20}:"{1,20}(None|({target_user}[^"]+))""",
    """"TargetDomainName"{1,20}:"{1,20}({domain}[^"]+)""",
    """"TargetLogonId"{1,20}:"{1,20}({logon_id}[^"]+)""",
    """"LogonType"{1,20}:"{1,20}({logon_type}[^"]+)""",
    """"TargetUserSid"{1,20}:"{1,20}({user_sid}[^"<,]+)""",
    """"record_id"{1,20}:({record_id}\d{1,100})""",
    """"task"{1,20}:"{1,20}({task_name}[^"]+)""",
    """"event_id"{1,20}:({event_code}\d{1,100})""",
    """"(?:winlog\.)?computer_name"{1,20}:"{1,20}({src_host}[^"]+)""",
    """"hostname"{1,20}:"{1,20}({host}[^"]+)""",
    """"action"{1,20}:"{1,20}({action}[^"]+)""",
    """"os":[^@]+?"name":"({os}[^"]+)""",
    """"SubjectLogonId"{1,20}:"{1,20}({logon_id}[^"]+)""",
    """"{1,20}activity_id"{1,20}:"{1,20}\{({activity_id}[^}]+)""",
    """"{1,20}ProviderName"{1,20}:"{1,20}({provider_name}[^"]+)""",
    """"{1,20}SubjectUserSid"{1,20}:"{1,20}({user_sid}[^"<,]+)""",
    """"{1,20}SubjectDomainName"{1,20}:"{1,20}({domain}[^"]+)""",
    """"user"{1,20}:"{1,20}(SYSTEM|-|({user}[^@"]+))""",
    """"{1,20}SubjectUserName"{1,20}:"{1,20}(SYSTEM|-|({user}[^"]+))""",
    """"{1,20}PrivilegeList"{1,20}:"{1,20}(-|({privileges}[^"]+))""",
    """"{1,20}SidHistory"{1,20}:"{1,20}(-|({sid_history}[^"]+))""",
    """"Keywords":"({outcome}[^"]+)"""
  ]

```