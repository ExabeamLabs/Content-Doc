#### Parser Content
```Java
{
Name = q-beyondtrust-process-created
  Vendor = BeyondTrust
  Product = BeyondTrust PowerBroker
  Lms = QRadar
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """ Message forwarded from """, """: accepted """ ]
  Fields = [
    """exabeam_endTime=({time}\d{1,100})""",
    """\s{1,100}Message forwarded from ({host}[\w\-.]{1,2000})""",
    """accepted ({process}({proccess_directory}.+?[\\\/])?({process_name}[^\\\/]{1,2000}?)) from ({user}[^\s@]{1,2000})@({src_host}[\w\-.]{1,2000}) to ({account}[^\s@]{1,2000})@({dest_host}[\w\-.]{1,2000})""",
  ]


}
```