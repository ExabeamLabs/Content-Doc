#### Parser Content
```Java
{
Name = ad-audit-json-4663
  DataType = "windows-4663"
  Conditions = [ """"EVENT_NUMBER":"4663"""", """"REMARKS":"An attempt was made to access an object."""" ]
  Fields = ${ADAuditParserTemplates.ad-audit-json-events.Fields}[
    """"CLIENT_HOST_NAME":"(-|({dest_ip}(\d{1,3}\.){3}\d{1,3})|({dest_host}[^"]{1,2000}))"""",
    """"CLIENT_IP_ADDRESS":"({dest_ip}[a-fA-F\d:.]{1,2000})"""",
    """"SOURCE":"(-|({src_host}[^"]{1,2000}))"""".
    """"OBJECT_NAME":"({file_path}({file_parent}[^"]{1,2000})\\{1,20}({file_name}[^"]{1,2000}))""",
    """"FILE_NAME":"({file_name}[^"]{1,2000}?(\.({file_ext}[^\."]{1,2000}))?)"""",
    """"ACCESSES":"({accesses}[^"]{1,2000})"""",
    """"PROCESS_NAME":"({process}[^"]{1,2000})"""",
    """"PROCESS_ID":"({process_id}[^"]{1,2000})""""
  ]

ad-audit-json-events = {
  Vendor = Microsoft
  Product = Windows
  Lms = Splunk
  TimeFormat = "epoch_sec"
  Fields = [
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """"TIME_GENERATED":"({time}\d{1,10})"""".
    """"CALLER_USER_NAME":"(-|({user}[^"]{1,2000}))"""".
    """"USERNAME":"({user}[^"]{1,2000})"""".
    """"LOGON_TYPE":"({logon_type}\d{1,100})"""".
    """"REMARKS":"({event_name}[^"]{1,2000})"""".
    """"EVENT_NUMBER":"({event_code}\d{1,100})"""".
    """"DOMAIN":"({domain}[^"]{1,2000})"""",
    """"(SOURCE|CLIENT)_PORT":"({src_port}\d{1,100})"""".
    """"WORKSTATION_NAME":"(-|({src_host_windows}[^"]{1,2000}))"""",
    """"LOGON_ID":"({logon_id}[^"]{1,2000})"""",
    """"USER_SID":"({user_sid}[^"]{1,2000})"""",
    """"ERROR_CODE":"(null|({result_code}[^"]{1,2000}))"""",
    """"EVENT_TYPE_TEXT":"({outcome}[^"]{1,2000})""""
  
}
```