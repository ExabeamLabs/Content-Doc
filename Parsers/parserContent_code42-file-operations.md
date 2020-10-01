#### Parser Content
```Java
{
Name = code42-file-operations
  Vendor = Code42
  Product = Code42 Incydr
  Lms = Direct
  DataType = "file-operations"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions= [ """Code42LogCollector,""", """KAFKA_CONNECT_SYSLOG: """]
  Fields = [
    """KAFKA_CONNECT_SYSLOG:\s+({host}[^,]+),(|("+({event_code}[^"]+)"+)|({=event_code}[^,]+)),(|("+({accesses}[^"]+)"+)|({=accesses}[^,]+)),(|("+({time}[^"]+)"+)|({=time}[^,]+)),(|("+[^"]+"+)|[^,]+),(|("+({file_path}[^"]+)"+)|({=file_path}[^,]+)),(|("+({file_name}[^"]+)"+)|({=file_name}[^,]+?(\.({file_ext}[^\.,]+))?)),(|("+[^"]+"+)|[^,]+),(|("+({file_type}[^"]+)"+)|({=file_type}[^,]+)),(|("+({bytes}[^"]+)"+)|({=bytes}[^,]+)),(|("+[^"]+"+)|[^,]+),(|("+({md5}[^"]+)"+)|({=md5}[^,]+)),(|("+({sha256}[^"]+)"+)|({=sha256}[^,]+)),(|("+({time_created}[^"]+)"+)|({=time_created}[^,]+)),(|("+({time_modified}[^"]+)"+)|({=time_modified}[^,]+)),(|("+({user_email}[^"]+)"+)|({=user_email}[^,]+)),(|("+[^"]+"+)|[^,]+),(|("+({user_uid}[^"]+)"+)|({=user_uid}[^,]+)),(|("+({src_host}[^"]+)"+)|({=src_host}[^,]+)),(|("+[^"]+"+)|[^,]+),(|("+({src_ip}[^"]+)"+)|({=src_ip}[^,]+)),(|("+({additional_info}[^"]+)"+)|({=additional_info}[^,]+)),(|("+({actor}[^"]+)"+)|({=actor}[^,]+)),(|("+({directory_id}[^"]+)"+)|({=directory_id}[^,]+)),(|("+({app}[^"]+)"+)|({=app}[^,]+)),(|("+({full_url}[^"]+)"+)|({=full_url}[^,]+)),(|("+({shared}[^"]+)"+)|({=shared}[^,]+)),(|("+({shared_with}[^"]+)"+)|({=shared_with}[^,]+)),(|("+({file_exposure_changed_to}[^"]+)"+)|({=file_exposure_changed_to}[^,]+)),(|("+({cloud_drive_id}[^"]+)"+)|({=cloud_drive_id}[^,]+)),(|("+({detection_source_alias}[^"]+)"+)|({=detection_source_alias}[^,]+)),(|("+({file_id}[^"]+)"+)|({=file_id}[^,]+)),(?:|("+({exposure_type}[^"]+)"+)|({=exposure_type}[^,]+)),(|("+({process_owner}[^"]+)"+)|({=process_owner}[^,]+)),(|("+({process_name}[^"]+)"+)|({=process_name}[^,]+)),(|("+({device_vendor}[^"]+)"+)|({=device_vendor}[^,]+)),(|("+({device_name}[^"]+)"+)|({=device_name}[^,]+)),(|("+({device_id}[^"]+)"+)|({=device_id}[^,]+)),(|("+({device_size}[^"]+)"+)|({=device_size}[^,]+)),(|("+({device_type}[^"]+)"+)|({=device_type}[^,]+)),(|("+({sync_destination}[^"]+)"+)|({=sync_destination}[^,]+))"""
]
  DupFields = ["file_path->file_parent"]
}
```