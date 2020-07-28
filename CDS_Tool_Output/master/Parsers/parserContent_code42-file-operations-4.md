#### Parser Content
```Java
{
Name = code42-file-operations-4
  Vendor = Code42
  Product = Code42
  Lms = Direct
  DataType = "file-operations"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions= [ """"fileCategoryByExtension"""",  """"eventType"""", """"osHostName"""]
  Fields = [ 
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"eventType"+:\s*"+({accesses}MODIFIED|DELETED|READ|CREATED)""",
    """"mimeTypeByExtension"+:\s*"+({mime}[^"]+)"""",
    """"tabUrl"+:\s*"+({full_url}[^"]+)"""",
    """"exposure"+:\s*\["*({log_source}[^"\]]+)"*\]""",
    """"processName"+:\s*"+({process_name}[^"]+)"""",
    """"userUid"+:\s*"+({user_uid}[^"]+)"""",
    """"deviceUid"+:\s*"+({device_id}[^"]+)"""",
    """"publicIpAddress"+:\s*"+({src_ip}[^"]+)"""",
    """"domainName"+:\s*"+({domain}[^"]+)"""",
    """"eventTimestamp"+:\s*"+({time}[^"]+)"""",
    """"filePath"+:\s*"+({file_path}[^"]+)"""",
    """"fileName"+:\s*"+({file_name}[^"]+)"""",
    """"fileCategory"+:\s*"+({file_type}[^"]+)"""",
    """"fileCategoryByExtension"+:\s*"+({file_ext}[^"]+)"""",
    """"fileSize"+:\s*({file_size}\d+)""",
    """"processOwner"+:\s*"+({user}[^"]+)"""",
    """"md5Checksum"+:\s*"+({md5}[^"]+)"""",
    """"sha256Checksum"+:\s*"+({sha256}[^"]+)"""",
    """"deviceUserName"+:\s*"+({user_email}[^"]+)"""",
    """"osHostName"+:\s*"+({dest_host}[^"]+)"""",
    """"windowTitle"+:\s*\["*({service}[^"\]]+)"*\]""",
  ]
  DupFields = ["file_path->file_parent", "dest_host->device_name"]
}
{
  Name = vectra-alert-3
  Product = Vectra
  Vendor = Vectra
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """vectra_timestamp""","""headend_addr""","""category""","""threat"""]
  Fields =[
    """({time}\d+-\d+-\d+T\d+:\d+:\d+)""",
    """"*d_type_vname"*:\s*"+({alert_name}[^"]+)""",
    """"*dvchost"*:\s*"+({host}[^"]+)""",
    """"*host_ip"*:\s*"+({src_ip}[^"]+)""",
    """"*href"*:\s*"+({malware_url}[^"]+)""",
    """"*detection_id"*:\s+({alert_id}\d+)""",
    """"*dd_bytes_sent"*:\s+({bytes_out}\d+)""",
    """"*dd_dst_port"*:\s+({dest_port}\d+)""",
    """"*category"*:\s+"*({alert_type}[^"]+)""",
    """"*dd_bytes_rcvd"*:\s+({bytes_in}\d+)""",
    """"*dd_dst_dns"*:\s+"+({web_domain}[^"]+)"+,""",
    """"*severity"*:\s+({alert_severity}\d+)""",
    """"*host_name"*:\s+"+({src_host}[^"]+)""",
    """"*dd_dst_ip"*:\s+"+({dest_ip}[^"]+)""",
    """"*dd_proto"*:\s+"+({protocol}[^"]+)"+,""",
    """"*threat"*:\s+({threat_id}\d+)"""
  ]
 }
 
 {
  Name = vectra-activity-1
  Product = Vectra
  Vendor = Vectra
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """vectra_timestamp""","""reason""","""action""","""src_name"""]
  Fields =[
    """({time}\d+-\d+-\d+T\d+:\d+:\d+)""",
    """({app}vectra)""",
    """"*dvchost"*:\s*"+({host}[^"]+)""",
    """"*src_name"*:\s*"+({src_host}[^"]+)""",
    """"*dest_name"*:\s*"+({dest_host}[^"]+)""",
    """"*src_ip"*:\s*"+({src_ip}[^"]+)""",
    """"*action"*:\s*"+({activity}[^"]+)""",
    """"*dest_ip"*:\s*"+({dest_ip}[^"]+)""",
    """"*reason"*:\s*"+({result}[^"]+)"""
  ]
 }

{
 Name = cef-sentinelone-activity
 Product = SentinelOne
 Vendor = SentinelOne
 Lms = Direct
 TimeFormat = "epoch"
 DataType = "app-activity"
 Conditions = [ """CEF:""", """destinationServiceName=""", """SentinelOne""" ]
 Fields = [
   """exabeam_host=([^=]+@\s*)?({host}\S+)""",
   """CEF:\d+\|([^\|]+\|){4}({activity}[^\|]+)""",
   """destinationServiceName=({app}[^\s]+)""",
   """timestamp\s\{\\n\s*millisecondsSinceEpoch:\s({time}\d+)""",
   """commandLine:\s*"+\\*({command_line}[^"]+)""",
   """pid:\s*({pid}\d+)""",
   """user\s*\{\\n\s+name:\s+"*({domain}[^\\]+)\\+({user}[^\s"]+)""",
   """user\s*\{\\n.+?sid:\s+"+({user_sid}[^"]+)""",
   """msg=({additional_info}.+?)\s+\w+=""",
   """fname=({object}.+?)\s+\w+=""",
   """path:\s+"+({process}({directory}[^."]+)\\({process_name}[^"]+))""",
 ]
}
{
  Name = netscope-dlp-alert-activity
  Vendor = Netskope
  Product = Netskope Active Platform
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """SkyFormation Cloud Apps Security""","""destinationServiceName=Netskope""","""alert_type""","""DLP"""]
  Fields =[  
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d+Z),""",
      """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
      """"dstip"+:"+({dest_ip}[^"]+)"""",
      """"file_type"+:"+({file_type}[^"]+)"""",
      """"app"+:"+({app}[^"]+)"""",
      """"device"+:"+({device_type}[^"]+)"""",
      """"alert_type"+:"+({alert_type}[^"]+)"""",
      """"hostname"+:"+({host}[^"]+)"""",
      """"policy"+:"+({alert_name}[^"]+)"""",
      """"action"+:"+({action}[^"]+)"""",
      """"referer"+:"+({referrer}[^"]+)"""",
      """"user"+:"+({user}[^"]+)"""",
      """"srcip"+:"+({src_ip}[^"]+)"""",
      """"category"+:"+({category}[^"]+)""""
      """"+activity"+:"+({activity}[^"]+)"+""",
      """"object"+:"+({file_name}[^"]+)"""",
      """"+ccl"+:"+({alert_severity}[^"]+)"+""",
      """"+md5"+:"+({md5}[^"]+)"+""",
      """"+request_id"+:({alert_id}[^,]+)""",
      """proto=({protocol}[^"]+)\srequestClientApplication""",
      """outcome=({outcome}[^ ]+)""",
      """ext_url=({full_url}[^ ]+)"""
    ]
}
${WatchGuardSParserTemplates.watch-guard-events}{
  Name = watchguard-event-1
  DataType = "network-connection"
  Conditions = [ """msg_id=""", """3000-0148""", """firewall:""" ]
}
```