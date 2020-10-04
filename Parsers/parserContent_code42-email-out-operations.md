#### Parser Content
```Java
{
Name = code42-email-out-operations
  Vendor = Code42
  Product = Code42 Incydr
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss:SSZ"
  Conditions= [ """"fileCategoryByExtension"""",  """"eventType":"EMAILED"""", """"osHostName""", """act=send""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"eventTimestamp"+:\s*"+({time}\d+-\d+-\d+T\d+:\d+:\d+Z)""",
    """"eventType"+:\s*"+({event_code}[^"]+)""",
    """"source":"+({log_source}[^"]+)"""",
    """"eventTimestamp"+:\s*"+({time}[^"]+)"""",
    """"fileName"+:\s*"+({file_name}[^"]+?(\.({file_ext}[^\."]+))?)"""",
    """"fileCategory"+:\s*"+({file_type}[^"]+)"""",
    """"fileSize"+:\s*({bytes}\d+)""",
    """"osHostName"+:\s*"+({dest_host}[^"]+)"""",
    """"eventType":"({alert_type}[^"]+)""",
    """"emailSender":"+({sender}[^"@]+@({external_domain_sender}[^"]+))"""",
    """"emailRecipients":\[*"+({recipient}[^"@]+@({external_domain_recipient}[^"]+))"""",
    """"emailSubject":\[*"+({subject}[^"]+)"""",
	
  ]
  DupFields = ["sender->email_user", "recipient->recipients" ]
}
{
  Name = code42-print-operations
  Vendor = Code42
  Product = Code42 Incydr
  Lms = Direct
  DataType = "print-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss:SSZ"
  Conditions= [ """"fileCategoryByExtension"""",  """"eventType":"PRINTED"""", """"osHostName"""]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"eventTimestamp"+:\s*"+({time}\d+-\d+-\d+T\d+:\d+:\d+Z)""",
    """"eventType"+:\s*"+({event_code}[^"]+)""",
    """"source":"+({log_source}[^"]+)"""",
    """"userUid"+:\s*"+({user_uid}[^"]+)"""",
    """"deviceUid"+:\s*"+({device_id}[^"]+)"""",
    """"processOwner"+:\s*"+({user}[^"]+)"""",
    """"deviceUserName"+:\s*"+({user_email}[^@"]+@[^"]+)"""",
    """"osHostName"+:\s*"+({dest_host}[^"]+)"""",
    """"actor"+:"+(({user_email}[^"@]+@[^"@]+)|({user}[^"]+))""",
    """"publicIpAddress":"+({dest_ip}[^"]+)"""",
    """"privateIpAddresses":\[*"+({src_ip}[^"]+)"""",
    """"printerName":"+({printer_name}[^"]+)"""",
    """"printJobName":"+\s*({object}[^"]+)"""",
  ]
  DupFields = ["dest_host->device_name"]
}

{
  Name = code42-file-operations-4
  Vendor = Code42
  Product = Code42 Incydr
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
    """"actor"+:"+(({user_email}[^"@]+@[^"@]+)|({user}[^"]+))""",
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

${SentinelOneParserTemplates.sentinelone-activity}{
  Name = sentinelone-web-activity
  DataType = "web-activity"
  Conditions = [ """CEF:""", """dproc=Deep Visibility Endpoint""", """destinationServiceName=SentinelOne""", """method:""", """http""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """,({time}\d+-\d+-\d+T\d+:\d+:\d+.\d+Z)""",
    """method:\s*"+({method}[^"]+)""",
    """url:\s*"+({full_url}({protocol}[^:\\\/\s,"]+):\/*({web_domain}[^\\\/\s:,"]+)(:({dest_port}\d+))({uri_path}\/[^\s\?"]*)?({uri_query}\?[^"\s]*)?)""",
    """\shttp.+?({top_domain}[^\/\.\s]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)"""
  ]
}
```