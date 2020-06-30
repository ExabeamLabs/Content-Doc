#### Parser Content
```Java
{
Name = s-prowatch-badge-access
    Vendor = ProWatch
    Lms = Splunk
    DataType = "physical-access"
    TimeFormat =  "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """REFID_TYP=""", """EVNT_DESCRP=""", """BADGENO""" ]
    Fields = [
      """EVNT_DAT="({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d).""",
      """CARDNO="({badge_id}[^"]+)"""",
      """LOCATION="({location_door}[^"]+)"""",
      """FNAME="({first_name}[^"]+)"""",
      """LNAME="({last_name}[^"]+)"""",
      """LOOP_DESCRP="({location_building}[^"]+)"""",
      """EVNT_DESCRP="({outcome}[^"]+)"""",
      """exabeam_host=([^=]*@\s*)?({host}[^\s]+)"""
    ]
  }
```