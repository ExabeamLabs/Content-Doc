#### Parser Content
```Java
{
Name = crowdstrike-usb-insert
    Vendor = CrowdStrike
    Product = Falcon
    Lms = Direct
    DataType = "usb-activity"
    TimeFormat = "epoch"
    Conditions = [ """"event_simpleName":"RemovableMediaVolumeMounted""""]
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
      """"{1,20}aip"{1,20}:"{1,20}({host}[^"]{1,2000})"{1,20}
```