using System.Web.Mvc;
using Demo.Shop.Persistence;

namespace Demo.Shop.Web
{
    public class OrderController : Controller
    {
        private readonly OrderRepository repository = new OrderRepository();

        // GET /orders/search?term=...
        public ActionResult Search(string term)
        {
            var orders = repository.Find(term);
            return View(orders);
        }

        // GET /orders/byid?id=...
        public ActionResult ById(int id)
        {
            return View(repository.FindById(id));
        }
    }
}
