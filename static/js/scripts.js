function goBack() {
    if (document.referrer) {
        window.history.back();
    } else {
        // Fallback if no history: redirect to dashboard
        window.location.href = "/dashboard";
    }
}
