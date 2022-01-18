#### Parser Content
```Java
{
Name = defender-atp-process
  DataType = "process-created"
  Conditions = [  """"Type":"AdvancedHuntingDeviceEvents_CL""" ,"""TimeGenerated""", """TenantId""" ]
  Fields = ${MicrosoftParserTemplates.defender-atp-events.Fields}[
    """"FileName"{1,20}:\s{0,100}"{1,20}({process_name}[^"]{1,2000})""",
    """"FolderPath"{1,20}:\s{0,100}"{1,20}({file_path}({file_parent}[^"]{0,2000}?[\\\/]{1,2000})?({file_name}[^"\\\/]{1,2000}?(\.({file_ext}\w+))?))"""",
]

defender-atp-events = {
    Vendor = Microsoft
    Product = Microsoft Defender ATP
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
    Fields = [
      """"time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
      """"DeviceName":"({host}[^"]{1,2000})""""
      """"LogonType":"({logon_type}[^"]{1,2000})"""",
      """"AccountName":"({user}[^"]{1,2000})"""",
      """"AccountDomain":"({domain}[^"]{1,2000})"""",
      """"InitiatingProcessFileName":"({process_name}[^"]{1,2000})"""",
      """"category":"({event_name}[^"]{1,2000})"""",
      """"ActionType":"({outcome}[^"]{1,2000})"""",
      """"RemoteIP":"({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
      """"Protocol":"({protocol}[^"]{1,2000})""""
    ]
    DupFields = ["host->dest_host"
}
```