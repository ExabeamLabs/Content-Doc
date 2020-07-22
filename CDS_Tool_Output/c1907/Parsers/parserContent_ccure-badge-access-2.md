#### Parser Content
```Java
{
Name = ccure-badge-access-2
    Vendor = CCURE
    Product = CCURE
    Lms = Direct
    DataType = "physical-access"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = ["""objectname2""","""objectname1""","""<Card>""", """<StateCode>"""]
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}\S+)""",
      """"messageutc":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)"""",
      """"objectname1":"({last_name}[^,"]+),\s*({first_name}[^"]+)"""",
      """"objectname2":"({location_door}[^"]+)"""",
      """<Card>({badge_id}.+?)</Card>""",
      """<StateCode>({outcome}.+?)</StateCode>""",
    ]
  }
  
  {
    Name = prowatch-badge-access
    Vendor = ProWatch
    Lms = Direct
    DataType = "physical-access"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [ """"evnt_dat":"""", """"evnt_descrp":"""", """"badge_employeeid":"""", """"cardstatus_descrp":"""" ]
    Fields = [
      """exabeam_host=({host}[\w.\-]+)""",
      """"location":"\s*({location_building}[^"]+?)\s*"""",
      """"descrp":"\s*({location_door}[^"]+?)\s*"""",
      """"evnt_dat":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
      """"cardno":"({badge_id}\d+)""",
      """"comp_name":"\s*({additional_info}[^"]+?)\s*"""",
      """"evnt_descrp":"\s*({outcome}[^"]+?)\s*"""",
      """"threat_lev":({threat_level}\d+)""",
      """"fname":"\s*({first_name}[^"]+?)\s*"""",
      """"lname":"\s*({last_name}[^"]+?)\s*"""",
      """"badge_employeeid":"\s*({employee_id}[^"]+?)\s*"""",
      """"cardstatus_descrp":"\s*({card_status}[^"]+?)\s*""""
    ]
  }
```