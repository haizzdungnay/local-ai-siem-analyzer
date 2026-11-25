[1mdiff --git a/ai_module/rag_data/playbooks.yaml b/ai_module/rag_data/playbooks.yaml[m
[1mindex 93255ae..35e1cae 100644[m
[1m--- a/ai_module/rag_data/playbooks.yaml[m
[1m+++ b/ai_module/rag_data/playbooks.yaml[m
[36m@@ -619,6 +619,13 @@[m [mplaybooks:[m
           <t_success> lấy từ kết quả câu hỏi đăng nhập thành công, không phải giờ alert 5760. Chú ý[m
           ~/.ssh/authorized_keys, /etc/passwd, /etc/sudoers*. 5501/5502 không có srcip.[m
 [m
[32m+[m[32m    # Tín hiệu đọc từ alert (Nguyên, 2026-11-20). Chỉ B3 có vế chứng minh được bằng alert:[m
[32m+[m[32m    # "tài khoản là root/dịch vụ". B2 cần V2 (đăng nhập thành công) nên không có select_if.[m
[32m+[m[32m    signals:[m
[32m+[m[32m      - id: S_sensitive_account[m
[32m+[m[32m        question: "Tài khoản bị gõ sai (data.dstuser, hoặc tên sau 'Failed password for' trong full_log) là root hoặc tài khoản dịch vụ (www-data, postgres, mysql, nginx, apache, nobody...)?"[m
[32m+[m[32m        match: {fields: [data.dstuser, data.srcuser], regex: '^(root|www-data|postgres|mysql|mariadb|nginx|apache|httpd|nobody|daemon|bin|sys|mail|ftp|redis|tomcat)$'}[m
[32m+[m
     branches:[m
       - id: B1_post_login_activity[m
         when: "V4 có sudo/tạo user/sửa file nhạy cảm sau một đăng nhập thành công đáng nghi"[m
[36m@@ -635,6 +642,7 @@[m [mplaybooks:[m
           - "Đề xuất (cần người phê duyệt): kết thúc phiên, đổi mật khẩu tài khoản đó, chặn srcip nếu chủ tài khoản không xác nhận"[m
       - id: B3_guessing_no_success[m
         when: "V2 rỗng, nhưng V1 có chuỗi dò (chậm, spraying, phân tán), hoặc tài khoản là root/dịch vụ, hoặc nguồn là máy nội bộ không có vai trò quản trị"[m
[32m+[m[32m        select_if: {any: [S_sensitive_account]}[m
         severity: medium[m
         actions:[m
           - "Ghi nhận dò mật khẩu; IP công cộng → đề xuất chặn/giới hạn tốc độ; máy nội bộ → kiểm máy nguồn có bị chiếm hoặc chạy script sai mật khẩu"[m
