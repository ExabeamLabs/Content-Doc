#### Parser Content
```Java
{
Name = s-crowdstrike-failed-logon
  Vendor = CrowdStrike
  Product = Falcon
  Lms = Splunk
  DataType = "failed-logon"
  TimeFormat = "epoch"
  Conditions = [ """"event_simpleName":"UserLogonFailed""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?(cc|({host}\S{1,2000}))""",
    """"timestamp":"({time}\d{1,100})"""",
    """"UserName":\s{0,100}"({user_email}[^"@]{1,2000}@[^"@]{1,2000})"""",
    """"UserName":\s{0,100}"(-|\/{1,20}|({user_fullname}({user_firstname}[^\s"]{1,2000})\s({user_lastname}[^"]{1,2000}))|({user}[^"@\s]{1,2000}))"""",
    """"UserSid":\s{0,100}"({user_sid}[^"]{1,2000})"""",
    """"event_simpleName":"({event_code}[^"]{1,2000})""",
    """"aid":"({aid}[^"]{1,2000})""",
    """"aip":\s{0,100}"({aip}[a-fA-F:\d.]{1,2000})"""",
    """"LogonType":"({logon_type}[^"]{1,2000})"""",
    """"name":"({event_name}[^"]{1,2000})"""",
    """"LogonDomain":"({domain}[^"]{1,2000})""""
  ]


}
```