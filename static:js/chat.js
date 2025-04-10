document.addEventListener('DOMContentLoaded', function() {
    // 소켓 연결 (전체 채팅용)
    const socket = io();
    
    // 공개 채팅 관련 요소
    const chatContainer = document.getElementById('chat-container');
    const messageInput = document.getElementById('message-input');
    const sendButton = document.getElementById('send-button');
    const username = document.getElementById('current-username')?.value;
    
    // 1:1 채팅 관련 요소
    const privateMessageContainer = document.getElementById('private-message-container');
    const privateMessageInput = document.getElementById('private-message-input');
    const privateSendButton = document.getElementById('private-send-button');
    
    // 공개 채팅 메시지 전송
    if (sendButton && messageInput) {
        sendButton.addEventListener('click', function() {
            sendMessage();
        });
        
        messageInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                sendMessage();
                e.preventDefault();
            }
        });
        
        function sendMessage() {
            const message = messageInput.value.trim();
            if (message) {
                socket.emit('send_message', {
                    message: message,
                    username: username
                });
                messageInput.value = '';
            }
        }
    }
    
    // 공개 채팅 메시지 수신
    socket.on('message', function(data) {
        if (chatContainer) {
            const isCurrentUser = username === data.username;
            
            const messageDiv = document.createElement('div');
            messageDiv.classList.add('chat-message', isCurrentUser ? 'message-sent' : 'message-received');
            
            // 메시지 내용 추가
            messageDiv.innerHTML = `
                <div>${data.message}</div>
                <div class="message-meta">
                    ${isCurrentUser ? '나' : data.username || '익명'}
                </div>
            `;
            
            chatContainer.appendChild(messageDiv);
            chatContainer.scrollTop = chatContainer.scrollHeight;
        }
    });
    
    // 1:1 채팅 메시지 전송
    if (privateSendButton && privateMessageInput) {
        privateSendButton.addEventListener('click', function() {
            const form = document.getElementById('private-message-form');
            if (form && privateMessageInput.value.trim()) {
                form.submit();
            }
        });
        
        privateMessageInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter' && !e.shiftKey) {
                const form = document.getElementById('private-message-form');
                if (form && privateMessageInput.value.trim()) {
                    e.preventDefault();
                    form.submit();
                }
            }
        });
    }
    
    // 메시지 컨테이너 스크롤을 최하단으로
    if (privateMessageContainer) {
        privateMessageContainer.scrollTop = privateMessageContainer.scrollHeight;
    }
    
    // 상품 필터링 및 정렬 기능
    const priceFilter = document.getElementById('price-filter');
    const sortSelect = document.getElementById('sort-select');
    
    if (priceFilter) {
        priceFilter.addEventListener('change', function() {
            applyFilters();
        });
    }
    
    if (sortSelect) {
        sortSelect.addEventListener('change', function() {
            applyFilters();
        });
    }
    
    function applyFilters() {
        const currentUrl = new URL(window.location.href);
        const searchParams = currentUrl.searchParams;
        
        if (priceFilter) {
            const prices = priceFilter.value.split('-');
            if (prices.length === 2) {
                searchParams.set('min_price', prices[0]);
                searchParams.set('max_price', prices[1]);
            }
        }
        
        if (sortSelect) {
            searchParams.set('sort_by', sortSelect.value);
        }
        
        window.location.href = currentUrl.toString();
    }
});