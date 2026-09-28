# Threat Model - json_search()

## 1. Actors / Roles

- Admin: có quyền quản trị hệ thống và được phép truy cập các thông tin nhạy cảm.
- Operator: vận hành và giám sát hệ thống mạng.
- Viewer: chỉ được xem các thông tin giám sát được phép.

## 2. Sensitive Assets

- apiKey: thông tin xác thực SNMP.
- managementIpAddress: địa chỉ quản trị thiết bị.
- Thông tin định danh thiết bị như hostname và serialNumber.

## 3. Trust Boundary

Trust boundary nằm giữa người dùng/role gọi hàm json_search()
và dữ liệu JSON chứa thông tin của hệ thống mạng.

Nếu json_search() không kiểm tra role trước khi trả kết quả,
người dùng có thể truy vấn các field mà role của họ không được
phép truy cập.

## 4. Threat Model

### Information Disclosure

Một user có role không đủ quyền, ví dụ viewer, có thể yêu cầu
json_search() tìm field apiKey. Nếu hàm không kiểm tra quyền
truy cập, apiKey có thể được trả về cho user không được phép.
