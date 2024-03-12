document.addEventListener('DOMContentLoaded', function () {
    const uploadForm = document.getElementById('uploadForm');
    const videoFileInput = document.getElementById('videoFile');
    const videoList = document.getElementById('videoList');

    uploadForm.addEventListener('submit', async function (event) {
        event.preventDefault();
        const formData = new FormData();
        formData.append('video', videoFileInput.files[0]);

        try {
            const response = await fetch('/upload', {
                method: 'POST',
                body: formData,
            });
            if (response.ok) {
                alert('Video uploaded successfully!');
                fetchVideoList();
            } else {
                throw new Error('Failed to upload video');
            }
        } catch (error) {
            console.error('Error uploading video:', error);
            alert('Failed to upload video');
        }
    });

    async function fetchVideoList() {
        try {
            const response = await fetch('/videos');
            if (response.ok) {
                const videoData = await response.json();
                renderVideoList(videoData);
            } else {
                throw new Error('Failed to fetch video list');
            }
        } catch (error) {
            console.error('Error fetching video list:', error);
            alert('Failed to fetch video list');
        }
    }

    function renderVideoList(videoData) {
        videoList.innerHTML = '';
        videoData.forEach(video => {
            const videoElement = document.createElement('video');
            videoElement.src = `/videos/${video.filename}`;
            videoElement.controls = true;

            const listItem = document.createElement('div');
            listItem.appendChild(videoElement);

            videoList.appendChild(listItem);
        });
    }

    fetchVideoList();
});