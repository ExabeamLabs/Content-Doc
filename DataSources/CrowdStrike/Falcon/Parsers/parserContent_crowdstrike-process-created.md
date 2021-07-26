#### Parser Content
```Java
{
Name = crowdstrike-process-created
    Vendor = CrowdStrike
    Product = Falcon
    Lms = Direct
    DataType = "process-created"
    IsHVF = true
    TimeFormat = "epoch"
    Conditions = [ """"event_simpleName":""", """"ProcessRollup2"""" ]
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
      """"aip":\s{0,100}"({host}[^"]{1,2000})""",
      """"aip":\s{0,100}"({dest_ip}[^"]{1,2000})"""
      """"timestamp":\s{0,100}"({time}\d{1,100})""",
      """"event_simpleName":\s{0,100}"({event_code}[^"]{1,2000})""",
      """"aid":\s{0,100}"({aid}[^"]{1,2000})""",
      """"CommandLine":\s{0,100}"\s{0,100}({command_line}[^,]{1,2000}?)\s{0,100}"{0,20}
```