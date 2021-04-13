#### Parser Content
```Java
{
Name = ad-json-member-removed-2008
  DataType = "windows-ds-access"
  Conditions = [""""event_id":""", """Microsoft-Windows-Security-Auditing""", """A member was removed from a security-enabled"""]
  Fields = ${WinParserTemplates.json-windows-events-1.Fields}[
    """({event_name}A member was removed from a security-enabled)""",
    """"+MemberSid"+:"+({account_id}[^"]+)""",
    """"TargetSid":"({group_id}[^\s"]+)"""
    """event_id"+:({event_code}\d+)""",
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
    """"(?:winlog\.)?computer_name"+:"+({src_host}[^"]+)""",
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