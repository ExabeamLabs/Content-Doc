#### Parser Content
```Java
{
Name = s-windows-event-4688
  DataType = "windows-process-created"
  Conditions = [ """LogType="WLS"""", """EventID="4688"""" ]

windows-events-wls= {
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}).+\sLogType""",
    """EventID="{1,20}({event_code}\d{1,100})"""",
    """Opcode.+ProcessName ="{1,20}(-|({process}({directory}(:?[\w:]{1,2000})?[^.]{1,2000}[\\\/]{1,2000}))({process_name}[^"]{1,2000}))"""",
    """ServiceName ="{1,20}({service_name}[^"]{1,2000})"""",
    """ServiceType="{1,20}({service_type}[^"]{1,2000})"""",
    """ServiceAccount="{1,20}({account_name}[^"]{1,2000})"""",
    """SubjectUserName ="{1,20}(-|({user}[^"]{1,2000}))"""",
    """SubjectDomainName ="{1,20}(-|({domain}[^"]{1,2000}))"""",
    """SubjectLogonId="{1,20}({logon_id}[^"]{1,2000})"""",
    """ProviderGuid="{1,20}({process_guid}[^"]{1,2000})"""",
    """CommandLine="{1,20}({command_line}[^"]{1,2000})"""",
    """SubjectUserSid="{1,20}({user_sid}[^"]{1,2000})"""",
    """SubjectUserName ="{1,20}(-|({user}[^"]{1,2000}))"""",
    """ObjectServer="{1,20}({object_server}[^"]{1,2000})"""",
    """ProcessId="{1,20}({process_id}[^"]{1,2000})"""",
    """Computer="{1,20}({dest_host}[^"]{1,2000})"""",
    """TargetDomainName ="{1,20}(-|({target_domain}[^"]{1,2000}))"""",
    """TargetUserName ="{1,20}(-|({target_user}[^"]{1,2000}))"""",
    """TargetLogonId="{1,20}({target_user_sid}[^"]{1,2000})"""",
    """TargetUserSid="{1,20}({target_user_sid}[^"]{1,2000})"""",
    """ExecutionProcessID="{1,20}({process_id}d+)"""",
    """FailureReason="{1,20}({failure_reason}[^"]{1,2000})"""",
    """WorkstationName ="{1,20}(-|({wokstation}[^"]{1,2000}))"""",
    """MemberName ="{1,20}({account_dn}[^"]{1,2000})"""",
    """MemberSid="{1,20}({account_id}[^"]{1,2000})"""",
    """LogonType="{1,20}({logon_type}[^"]{1,2000})"""",
    """SubStatus="{1,20}({result_code}[^"]{1,2000})"""",
    """LogonProcessName ="({auth_process}[^"]{1,2000})"""",
    """KeyLength="({key_length}\d{1,2000})"""",
    """AuthenticationPackageName ="({auth_package}[^"]{1,2000})"""",
    """IpAddress="(-|({src_ip}[a-fA-F\d:.]{1,2000}))""""
    ]
    DupFields = [ "dest_host->host" 
}
```