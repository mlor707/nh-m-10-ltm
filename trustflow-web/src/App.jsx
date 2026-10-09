import { useState } from 'react'

function App() {
  const [file, setFile] = useState(null)

  const handleFileChange = (e) => {
    setFile(e.target.files[0])
  }

  const handleUpload = () => {
    if (!file) {
      alert("Vui lòng chọn một file trước!")
      return
    }
    // Tạm thời hiển thị thông báo, logic mã hóa sẽ thêm vào sau
    alert(`Đã chọn file: ${file.name}\nChuẩn bị tiến hành mã hóa AES-GCM...`)
  }

  return (
    <div style={{ padding: '2rem', fontFamily: 'sans-serif', maxWidth: '500px', margin: '0 auto' }}>
      <h1 style={{ color: '#2c3e50' }}>TrustFlow</h1>
      <p style={{ color: '#7f8c8d', marginBottom: '2rem' }}>Hệ thống Truyền tải Tài liệu Nội bộ An toàn (Zero-Knowledge)</p>
      
      <div style={{ border: '1px solid #bdc3c7', padding: '1.5rem', borderRadius: '8px' }}>
        <input 
          type="file" 
          onChange={handleFileChange} 
          style={{ marginBottom: '1.5rem', display: 'block' }}
        />
        
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', marginBottom: '1.5rem' }}>
          <label>
            Số lần tải tối đa:
            <select defaultValue="1" style={{ marginLeft: '10px', padding: '4px' }}>
              <option value="1">1 lần</option>
              <option value="3">3 lần</option>
              <option value="5">5 lần</option>
            </select>
          </label>
          <label>
            Tự hủy sau:
            <select defaultValue="10" style={{ marginLeft: '10px', padding: '4px' }}>
              <option value="5">5 phút</option>
              <option value="10">10 phút</option>
              <option value="60">1 giờ</option>
            </select>
          </label>
        </div>

        <button 
          onClick={handleUpload} 
          style={{ 
            backgroundColor: '#3498db', 
            color: 'white', 
            border: 'none', 
            padding: '10px 20px', 
            borderRadius: '4px', 
            cursor: 'pointer',
            width: '100%'
          }}>
          Mã hóa & Tải lên
        </button>
      </div>
    </div>
  )
}

export default App