function Loading({ height = 220 }) {
    return (
        <div className="loading" style={{ minHeight: height }}>
            <div className="spinner-ring"></div>
            <p>Loading data…</p>
        </div>
    );
}

export default Loading;
