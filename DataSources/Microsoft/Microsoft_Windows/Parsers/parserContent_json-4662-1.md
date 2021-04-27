#### Parser Content
```Java
{
Name = json-4662-1
  DataType = "windows-privileged-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"EventID":"4662"""", """An operation was performed on an object""" ]
  Fields = ${WinParserTemplates.json-windows-events-1.Fields}[
    """"Computer":"({host}[^"]+)"""",
    """"TimeCreated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """({event_name}An operation was performed on an object)""",
    """({event_code}4662)""",
    """"ObjectName":"({object}[^"]+)"""",
    """"ObjectServer":"({object_server}[^"]+)"""",
    """"ObjectType":"({activity_type}[^"]+)"""",
    """"LogonID":"({logon_id}[^"]+)"""",
    """"OperationType":"({activity}[^"]+)"""",
    """"AdditionalInfo":"(?:-|({additional_info}[^"]+))""""
  ]
   DupFields = ["host->dest_host"]
}
json-windows-events-1 = {
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)\s[^\s]+\sSkyformation""",
    """"+created"+:"+({time}[^"]+)""",
    """requestClientApplication=({app}[^=]+?)\s\w+=""",
    """({event_name}An account was logged off)""",
    """"keywords"+:\["+({outcome}[^"]+)""",
    """"pid"+:({pid}\d+)""",
    """thread"+:[^@]+?"+id"+:({thread_id}\d+)""",
    """"TargetUserName"+:"+(None|({target_user}[^"]+))""",
    """"TargetDomainName"+:"+({domain}[^"]+)""",
    """"TargetLogonId"+:"+({logon_id}[^"]+)""",
    """"LogonType"+:"+({logon_type}[^"]+)""",
    """"TargetUserSid"+:"+({user_sid}[^"<,]+)""",
    """"record_id"+:({record_id}\d+)""",
    """"task"+:"+({task_name}[^"]+)""",
    """"event_id"+:({event_code}\d+)""",
    """"computer_name"+:"+({src_host}[^"]+)""",
    """"hostname"+:"+({host}[^"]+)""",
    """"action"+:"+({action}[^"]+)""",
    """"os":[^@]+?"name":"({os}[^"]+)""",
    """"SubjectLogonId"+:"+({logon_id}[^"]+)""",
    """"+activity_id"+:"+\{({activity_id}[^}]+)""",
    """"+ProviderName"+:"+({provider_name}[^"]+)""",
    """"+SubjectUserSid"+:"+({user_sid}[^"<,]+)""",
    """"+SubjectDomainName"+:"+({domain}[^"]+)""",
    """"user"+:"+(SYSTEM|-|({user}[^@"]+))""",
    """"+SubjectUserName"+:"+(SYSTEM|-|({user}[^"]+))""",
    """"+PrivilegeList"+:"+(-|({privileges}[^"]+))""",
    """"+SidHistory"+:"+(-|({sid_history}[^"]+))""",
    """"Keywords":"({outcome}[^"]+)"""
  ]

```