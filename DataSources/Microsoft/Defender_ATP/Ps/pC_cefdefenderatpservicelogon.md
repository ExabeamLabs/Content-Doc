#### Parser Content
```Java
{
Name = cef-defender-atp-service-logon
  DataType = "logon"
  Conditions = ["""AdvancedHunting-DeviceLogonEvents""", """"LogonType":"Service"""", """"InitiatingProcessParentFileName":"""]

cef-defender-atp-events = {
    Vendor = Microsoft
    Product = Defender ATP
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
      """"Protocol":"(MICROSOFT_AUTHENTICATION_PACKAGE_V1_0|({protocol}[^"]{1,2000}))""""
      """LogonId":(null|({logon_id}[^:]{1,2000}?)),""",
      """InitiatingProcessFolderPath":"({process}[^"]{1,2000}?)",""",
      """InitiatingProcessFileName":"({process_name}[^:]{1,2000}?)",""",
      """InitiatingProcessCommandLine":"({command_line}[^<]{1,2000}?)\s{0,100}","InitiatingProcess""",
      """InitiatingProcessId":({pid}[^:]{1,2000}?),""",
      """DeviceId":"({device_id}[^:]{1,2000}?)",""",
      """InitiatingProcessMD5":"({md5}[^:]{1,2000}?)","""
    ]
    DupFields = ["host->dest_host"
}
```