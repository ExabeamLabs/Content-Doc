#### Parser Content
```Java
{
Name = cef-rightcrowd-failed-physical-access-2
  DataType = "failed-physical-access"
  Conditions = [ """CEF:""","""|RightCrowd|RightCrowd|""","""|PIN code error""","""eventId=""" ]  

rightcrowd-physical-access = {
    Vendor = RightCrowd
    Product = RightCrowd
    Lms = Splunk
    TimeFormat = "epoch"
    Fields = [
      """ahost=({host}[^\s]{1,2000})""",
      """art=({time}[^\s]{1,2000})""",
      """CEF:[^|]{1,2000}\|([^|]{0,2000}\|){4}({event_name}[^|]{1,2000})""",
      """eventId=({event_code}\d{1,100})""",
      """cn1=({badge_id}\d{1,100})""",
      """cs1=({badge_reader}[^=]{1,2000}?)\s{0,100}\w+=""",
      """categoryOutcome=(\/)?({outcome}[^\s]{1,2000})""",
      """suser=({user}[^=]{1,2000}?)\s{0,100}\w+=""",
      """suid=({user_fullname}({user_lastname}[A-Z][a-z]{1,2000})\s{0,100}({user_firstname}\w*))\s{1,100}\w+=""",
      """cs5=({site_state}[^\s]{1,2000})""",
      """agt=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """cs6=({area_classification}[^=]{1,2000})\s{1,100}\w+=""",
      """cs4=({site_id}\d{1,100})""",
      """cs3=({site_name}[^=]{1,2000})\s{1,100}\w+=""",
      """cs2=({badge_status}[^=]{1,2000})\s{1,100}\w+="""
    ]
    DupFields = [ "badge_reader->location_door" 
}
```