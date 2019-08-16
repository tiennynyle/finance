#import os
import datetime

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd
#export API_KEY=pk_7da151e50d5a4c9cb4e63305de2cb970


# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    #Check remaining cash
    check_cash = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id = session["user_id"])
    cash_remained = check_cash[0]["cash"]

    stocks = db.execute("SELECT symbol, SUM(shares) FROM purchase_history WHERE user_id = :user_id GROUP BY symbol;", user_id=session["user_id"])
    for stock in stocks:
        quote = lookup(symbol)
        stock["name"] = quote["name"]
        stock["price"] = quote["price"]
        stock["total"] = float(index_price) * int(stock["SUM(shares)"])
    index_grandtotal = stock["total"] + cash_remained
    return render_template("index.html", stocks=stocks, index_grandtotal = index_grandtotal, cash_remained = cash_remained)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        if not symbol:
            return apology("must provide symbol", 406)
        elif not shares:
            return apology("must provide number of shares", 406)

        quote = lookup(symbol)
        if quote == None:
            return apology("invalid symbol",406)

        #Check if enough cash
        rows = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])

        price_per_share = float(quote["price"])
        total_price = price_per_share * float(shares)

        available_cash = rows[0]["cash"]

        if available_cash < total_price:
            return apology("not enough cash to complete the transaction", 406)

        cash_remained = available_cash - total_price
        date_purchased = datetime.datetime.now()
        #update cash in database after transaction
        db.execute("UPDATE users SET cash = :cash_remained WHERE id = :user_id",\
                    cash_remained=cash_remained, user_id=session["user_id"])
        #check if the stock has been bought by that user
        purchased_stock = db.execute("SELECT shares FROM purchase_history WHERE id = :user_id AND symbol =:symbol", user_id=session["user_id"], symbol=symbol)

        if len(purchased_stock) == 0:
            db.execute("INSERT INTO purchase_history (user_id, symbol, shares, price, `date purchased`) VALUES(:user_id, :symbol, :shares, :price, :date_purchased)",user_id=session["user_id"],symbol=symbol,shares=shares, price=price_per_share, date_purchased=date_purchased)
        else:
            updated_shares = purchased_stock[0]["shares"] + int(shares)
            db.execute("UPDATE purchased_history SET shares = :updated_shares WHERE user_id =:user_id AND symbol =:symbol", user_id=session["user_id"], symbol=symbol, updated_shares=updated_shares)

        flash("Transaction completed!")
        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""
    username = request.args.get("username")
    check_username = db.execute("SELECT username FROM users WHERE username =:username", username = username)

    if not check_username and len(username) > 1:
        return jsonify(True)
    else:
        return jsonify(False)

@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    stocks = db.execute("SELECT symbol, shares, price, `date purchased` FROM purchase_history WHERE user_id = :user_id", user_id=session["user_id"])
    return render_template("history.html", stocks=stocks)

@app.route("/passwordchange", methods=["GET", "POST"])
@login_required
def passwordchange():
    """Let users change password"""
    if request.method == "POST":
        current_password = request.form.get("current-password")
        new_password = request.form.get("new-password")
        new_password_confirmation = request.form.get("new-password-confirmation")

        if not current_password:
            return apology("must provide username", 410)

        # Ensure password was submitted
        elif not new_password:
            return apology("must provide password", 410)

        # Ensure password confirmation was submitted
        elif not new_password_confirmation:
            return apology("must confirm password", 410)

        # Ensure password matches confirmation
        elif new_password != new_password_confirmation:
            return apology("Password must match Confirmation", 410)
        #security
        hash = generate_password_hash(new_password)

        #update db with new password
        db.execute("UPDATE users SET hash=:hash WHERE id = :user_id",\
                     hash=hash, user_id=session["user_id"])
        flash("Password Changed!")
        return redirect("/")
    else:
        return render_template("passwordchange.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        quote = lookup(request.form.get("symbol"))

        if not quote:
            return apology("must provide quote", 405)
        if quote == None:
            return apology("invalid symbol",405)
        return render_template("quoted.html", quote=quote)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensure username was submitted
        if not username:
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not password:
            return apology("must provide password", 400)

        # Ensure password confirmation was submitted
        elif not confirmation:
            return apology("must confirm password", 400)

        # Ensure password matches confirmation
        elif password != confirmation:
            return apology("Password must match Confirmation", 400)
        #security
        hash = generate_password_hash(password)
        new_user = db.execute("INSERT INTO users(username, hash) VALUES (:username, :hash)", username = username, hash = hash)

        # unique username constraint violated?
        if not new_user:
            return apology("username taken", 400)

        # Remember which user has logged in
        session["user_id"] = new_user

        # Display a flash message
        flash("Registered!")

        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("register.html")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    stocks_owned = db.execute("SELECT symbol, shares FROM purchase_history WHERE user_id = :user_id", user_id=session["user_id"])
    available_shares = stocks_owned[0]["shares"]

    if request.method == "POST":

        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        if not symbol:
            return apology("must provide symbol", 408)
        elif not shares:
            return apology("must provide number of shares", 408)
        elif shares > available_shares:
            return apology("You don't have enough shares of this stock", 408)
        date_purchased = datetime.datetime.now()
        #update shares
        price_per_share = float(lookup(symbol)["price"])
        total_price = price_per_share * shares
        stocks_sold = db.execute("INSERT INTO purchase_history (user_id, symbol, shares, price, `date purchased`) VALUES(:user_id, :symbol, :shares, :price, :date_purchased)",user_id=session["user_id"],symbol=symbol,shares=(shares*(-1)), price=price_per_share, date_purchased=date_purchased)

        #update cash
        check_cash = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])
        cash_remained = check_cash[0]["cash"] + total_price
        db.execute("UPDATE users SET cash = :cash_remained WHERE id = :user_id",\
                    cash_remained=cash_remained, user_id=session["user_id"])
        flash("Sold!")
        return redirect("/")
    else:
        return render_template("sell.html",stocks_owned = stocks_owned)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
