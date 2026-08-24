import { Routes, Route } from "react-router-dom";

import Layout from "./components/Layout";

import Dashboard from "./pages/Dashboard";
import Monitoring from "./pages/Monitoring";
import Analytics from "./pages/Analytics";
import Alerts from "./pages/Alerts";
import NetworkMap from "./pages/NetworkMap";
import Reports from "./pages/Reports";
import Settings from "./pages/Settings";
import About from "./pages/About";

function App() {

    return (

        <Routes>

            <Route
                path="/"
                element={
                    <Layout>
                        <Dashboard />
                    </Layout>
                }
            />

            <Route
                path="/monitoring"
                element={
                    <Layout>
                        <Monitoring />
                    </Layout>
                }
            />

            <Route
                path="/analytics"
                element={
                    <Layout>
                        <Analytics />
                    </Layout>
                }
            />

            <Route
                path="/alerts"
                element={
                    <Layout>
                        <Alerts />
                    </Layout>
                }
            />

            <Route
                path="/network"
                element={
                    <Layout>
                        <NetworkMap />
                    </Layout>
                }
            />

            <Route
                path="/reports"
                element={
                    <Layout>
                        <Reports />
                    </Layout>
                }
            />

            <Route
                path="/settings"
                element={
                    <Layout>
                        <Settings />
                    </Layout>
                }
            />

            <Route
                path="/about"
                element={
                    <Layout>
                        <About />
                    </Layout>
                }
            />

        </Routes>

    );

}

export default App;