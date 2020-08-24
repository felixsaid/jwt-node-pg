import React, { Fragment, useState, useEffect } from "react";
import { toast } from "react-toastify";

const Dashboard = ({ setAuth }) => {
  const [name, setName] = useState("");

  async function getName() {
    try {
      const response = await fetch("http://localhost:5000/v4/dashboard", {
        method: "GET",
        headers: { token: localStorage.token },
      });

      const parseRes = await response.json();

      setName(parseRes.user_name);
    } catch (err) {
      console.error(err.message);
    }
  }

  const logOut = (e) => {
    e.preventDefault();

    localStorage.removeItem("token");
    setAuth(false);

    toast.success("User session was succesfully ended!");
  };

  useEffect(() => {
    getName();
  }, []);

  return (
    <Fragment>
      <h1 className="text-center my-5">Dashboard</h1>
      <h4 className="text-center">Welcome {name}</h4>

      <div className="row">
        <div className="col text-center my-5">
          <button className="btn btn-primary" onClick={(e) => logOut(e)}>
            Logout
          </button>
        </div>
      </div>
    </Fragment>
  );
};

export default Dashboard;
