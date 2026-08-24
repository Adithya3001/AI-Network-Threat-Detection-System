import Sidebar from "./Sidebar";
import Header from "./Header";
import Notification from "./Notification";

function Layout({ children }) {
    return (
        <div className="layout">
            <Notification />
            <Sidebar />
            <div className="main-content">
                <Header />
                <main className="content-area">{children}</main>
            </div>
        </div>
    );
}

export default Layout;
