#### Parser Content
```Java
{
Name = json-4778
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4778"
    TimeFormat = "epoch"
    Conditions = ["""A session was reconnected to a Window Station""", """"EventID":4778"""]
    Fields = [
      """"EventTime":({time}\d{1,100})""",
      """"Hostname":"({host}[\w.-]{1,2000}?)"""",
      """"EventID":({event_code}\d{1,100})""",
      """({event_name}A session was reconnected to a Window Station)""",
      """"AccountName":"({user}[^"]{1,2000})""",
      """"AccountDomain":"({domain}[^"]{1,2000})""",
      """"LogonID":"({logon_id}[^"]{1,2000})""",
      """"ClientName":"({src_host}[^"]{1,2000})""",
      """"ClientAddress":"({src_ip}[a-fA-F\d.:]{1,2000}?)""""
    ]
    DupFields = [ "host->dest_host" ]
  }
```