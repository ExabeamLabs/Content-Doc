#### Parser Content
```Java
{
Name = json-5140-2
    Vendor = Microsoft
    Product = Windows
    Lms = Direct
    DataType = "share-access"
    TimeFormat = "yyyy-dd-MM'T'HH:mm:ss.SSSZ"
    Conditions = ["""A network share object was accessed""", """"SubjectUserName":""", """"event_id":"5140""",""""Microsoft-Windows-Security-Auditing"""",""""ShareName":""""]
    Fields = [
      """({event_name}A network share object was accessed)""",
      """"created":"({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z)"""",
      """({event_code}5140)""",
      """"SubjectLogonId":"({logon_id}[^"]{1,2000})"""",
      """"AccessList":"({accesses}[^"]{1,2000})"""",
      """"ShareLocalPath":"[\\?]{0,2000}(({share_path}(({d_parent}.+?)\\)?(|({d_name}[^\\]{1,2000}?)))\\?)"""",
      """"SubjectUserName":"({user}[^"]{1,2000})"""",
      """"SubjectDomainName":"({domain}[^"]{1,2000})"""",
      """"IpAddress":"({src_ip}[A-Fa-f:\d.]{1,2000})"""",
      """({accesses}Read)""",
      """"ShareName":"([\\*]{1,2000})?({share_name}[^"]{1,2000})"""",
      """"outcome":"({outcome}\w+)"""",
      """"host":"({host}[\w.\-]{1,2000})"""",
      """Logon ID:\s({logon_id}[^\s]{1,2000})""",
      """"IpPort":"({src_port}\d{1,100})"""",
      """"SubjectUserSid":"({user_sid}[^"]{1,2000})"""",
      """"action":"({activity}[^"]{1,2000})""",
    ]
    DupFields=[ "host->dest_host" ]


}
```