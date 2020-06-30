#### Parser Content
```Java
{
Name = box-activity
  Vendor = Box
  Product = Box
  Lms = Splunk
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ "created_by_login=", "created_by_name=", "source_item_name=", "event_type=" ]
  Fields = [
    """created_at="+({time}[^"]+)"""",
    """exabeam_host=({host}[^\s]+)""",
    """created_by_login="+({user}[^"@]+)""",
    """accessible_by_login="+({object}[^"@]+)""",
    """source_user_email="+({object}[^@]+)""",
    """({file_type}folder)""",
    """source_item_name="+({file_name}[^"]+)""",
    """source_item_type="+({file_type}[^"]+)""",
    """source_folder_name="+({file_name}[^"]+)""",
    """source_parent_name="+({file_parent}[^"]+)""",
    """additional_details_size="({bytes}\d+)""",
    """ip_address="+({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """event_type="+({accesses}[^"]+)""",
    """created_by_login="({user_email}.*?@([\.\w+]+\.)?({email_domain}[^\.\s]+\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ch)))"""
  ]
  DupFields = [ "accesses->event_code" ]
}
```