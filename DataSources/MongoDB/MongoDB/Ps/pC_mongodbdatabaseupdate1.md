#### Parser Content
```Java
{
Name = mongodb-database-update-1
  Conditions = [ """"atype" :""", """"createDatabase"""", """"ts"""", """"local" : {""", """"param" :""", """"users" : [""" ]

mongodb-database-events = {
    Vendor = MongoDB
    Product = MongoDB
    Lms = Splunk
    DataType = "database-update"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
      """"\$date"\s{0,100}:\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,3}[+\-]\d{1,4})""",
      """"user"\s{0,100}:\s{0,100}"({user}[^"]{1,2000})"""",
      """"users"\s{0,100}:\s{0,100}\[[^\]]{1,2000}"db"\s{0,100}:\s{0,100}"({db_user}[^"]{1,2000})"""",
      """"atype"\s{0,100}:\s{0,100}"({db_operation}[^"]{1,2000})"""",
      """"ns"\s{0,100}:\s{0,100}"({database_name}[^"\.]{1,2000})""",
      """"result"\s{0,100}:\s{0,100}({result}[^\}]{1,2000}?)\s{0,100}\}""",
      """"local"\s{0,100}:\s{0,100}\{\s{0,100}"ip"\s{0,100}:\s{0,100}"({src_ip}[a-fA-F\d:.]{1,2000})"""",
      """"local"\s{0,100}:\s{0,100}\{[^\}]{1,2000}?"port"\s{0,100}:\s{0,100}({src_port}\d{1,100})""",
      """"remote"\s{0,100}:\s{0,100}\{\s{0,100}"ip"\s{0,100}:\s{0,100}"({dest_ip}[a-fA-F\d:.]{1,2000})"""",
      """"remote"\s{0,100}:\s{0,100}\{[^\}]{1,2000}?"port"\s{0,100}:\s{0,100}({dest_port}\d{1,100})"""
    
}
```