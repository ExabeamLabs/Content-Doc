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
      """"Hostname":"({host}[\w.-]+?)"""",
      """"EventID":({event_code}\d{1,100})""",
      """({event_name}A session was reconnected to a Window Station)""",
      """"AccountName":"({user}[^"]+)""",
      """"AccountDomain":"({domain}[^"]+)""",
      """"LogonID":"({logon_id}[^"]+)""",
      """"ClientName":"({src_host}[^"]+)""",
      """"ClientAddress":"({src_ip}[a-fA-F\d.:]+?)""""
    ]
    DupFields = [ "host->dest_host" ]
  }
```