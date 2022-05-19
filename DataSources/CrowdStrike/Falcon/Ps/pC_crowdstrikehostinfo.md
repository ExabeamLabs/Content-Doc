#### Parser Content
```Java
{
Name = crowdstrike-host-info
    Vendor = CrowdStrike
    Product = Falcon
    Lms = Direct
    DataType = "logon"
    TimeFormat = "epoch"
    Conditions = [ """"event_simpleName":"HostInfo"""", """"aid"""" ]
    Fields = [
      """"timestamp":"({time}\d{1,100})"""",
      """"{1,20}MachineDn"{1,20}:"{1,20}CN\\*(=|u003d)?({dest_host}[^,]{1,2000})""",   
      """"aid":"({aid}[^"]{1,2000})""",
      """"event_simpleName":"({event_code}[^"]{1,2000})""",
      """suser=(system|({user}[^\s]{1,2000}))"""
    ]
    DupFields = [ "dest_host->host" ] 
  

}
```